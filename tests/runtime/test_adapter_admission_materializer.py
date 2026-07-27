from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom import adapter_admission_materializer as materializer
from faultloom import adapter_admission_verifier as verifier
from faultloom import model_utility_sandbox
from faultloom import t40_faultloom_admission as consumer
from faultloom import t40_faultloom_install as install
from faultloom.model_utility_process import BoundedProcessLaunch
from faultloom.model_utility_proxy_models import LocalModelProcessConfig
from faultloom.t40_formal_producer_binding import materialize_formal_producer_binding
from faultloom_protocol import canonical_json_bytes, sha256_digest
from faultloom_sdk import AdapterAdmissionState, reference_registry


def _spec() -> dict[str, object]:
    return {
        "schema_version": "faultloom.adapter-admission-input.v1",
        "bundle_id": "adapter-reference-admission-1",
        "session_id": "adapter-admission.session-1",
        "evaluator_challenge": "0123456789abcdef" * 4,
        "staging_manifest_path": None,
        "staging_manifest_sha256": None,
        "producer_state": "adapter-admission-producer.sequence",
        "verifier_state": "adapter-admission-verifier.sequence",
        "output": "adapter-admission-bundle.json",
        "timeout_seconds": 20,
        "maximum_response_bytes": 65_536,
    }


def _prepare(root: Path) -> None:
    root.mkdir(mode=0o700)
    path = root / "adapter-admission-input.json"
    path.write_bytes(canonical_json_bytes(_spec()))
    path.chmod(0o600)


def _key_fd(root: Path, name: str, seed: bytes) -> int:
    path = root / name
    path.write_bytes(seed)
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC)


def _staging_fixture(root: Path) -> tuple[Path, materializer.AdapterAdmissionInput]:
    generation = root / "generation-001"
    site = generation / "site-packages"
    package = site / "fixture_pkg"
    package.mkdir(parents=True, mode=0o700)
    generation.chmod(0o700)
    site.chmod(0o700)
    package.chmod(0o700)
    installed = package / "module.py"
    installed.write_bytes(b"VALUE = 1\n")
    installed.chmod(0o400)
    launcher = generation / "isolated-launcher"
    launcher.write_bytes(b"raise SystemExit(0)\n")
    launcher.chmod(0o400)
    tree_payload = {
        "directories": [
            {"path": ".", "mode": 0o700},
            {"path": "fixture_pkg", "mode": 0o700},
        ],
        "files": [
            {
                "path": "fixture_pkg/module.py",
                "sha256": materializer._digest_bytes(installed.read_bytes()),
                "mode": 0o400,
            }
        ],
    }
    manifest = {
        "schema": "faultloom.ops.t40-formal-staging.v1",
        "generation_id": generation.name,
        "generation_root": str(generation),
        "sources": [
            {
                "role": role,
                "sha256": materializer._digest_bytes(role.encode()),
                "size": len(role),
            }
            for role in materializer._STAGING_SOURCE_ROLES
        ],
        "installed_tree": {**tree_payload, "sha256": sha256_digest(tree_payload)},
        "launcher": {
            "argv_prefix": [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                str(launcher),
            ],
            "invocation": [
                "--module",
                "<installed-module>",
                "--callable",
                "<entrypoint>",
                "--",
                "<arguments>",
            ],
            "forbidden_environment": list(materializer._FORBIDDEN_STAGING_ENVIRONMENT),
            "forbidden_environment_prefixes": list(materializer._FORBIDDEN_STAGING_PREFIXES),
            "fixed_environment": materializer._FIXED_STAGING_ENVIRONMENT,
            "isolation_flags": ["-I", "-S", "-B"],
            "module_origin": "strictly-under-site-root",
            "site_root": str(site),
            "site_root_mode": 0o700,
            "sha256": materializer._digest_bytes(launcher.read_bytes()),
            "mode": 0o400,
        },
    }
    raw = canonical_json_bytes(manifest)
    manifest_path = generation / "staging-manifest.json"
    manifest_path.write_bytes(raw)
    manifest_path.chmod(0o400)
    spec = materializer.AdapterAdmissionInput.model_validate(
        _spec()
        | {
            "staging_manifest_path": str(manifest_path),
            "staging_manifest_sha256": materializer._digest_bytes(raw),
        }
    )
    return generation, spec


def _signed_install_profile(root: Path) -> tuple[Path, bytes, dict[str, object]]:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    public = key.public_key().public_bytes_raw()
    payload: dict[str, object] = {field: "fixture" for field in install._PROFILE_FIELDS}
    payload["schema"] = "faultloom.ops.t40-formal-install-profile.v1"
    payload["adapter_admission_bundle_sha256"] = materializer._digest_bytes(b"bundle")
    payload["staging_manifest_sha256"] = materializer._digest_bytes(b"staging")
    payload_digest = materializer._digest_bytes(canonical_json_bytes(payload))
    signing = canonical_json_bytes({"payload": payload, "payload_digest": payload_digest})
    envelope = {
        "payload": payload,
        "payload_digest": payload_digest,
        "signature": base64.urlsafe_b64encode(key.sign(signing)).rstrip(b"=").decode(),
    }
    path = root / "profile.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(envelope))
    path.chmod(0o600)
    return path, public, payload


@contextmanager
def _held_formal_launch(
    config: LocalModelProcessConfig, stdin: bytes = b""
) -> Generator[BoundedProcessLaunch, None, None]:
    descriptors = (
        os.open(os.devnull, os.O_RDONLY),
        os.open(os.devnull, os.O_RDONLY),
        os.open(os.devnull, os.O_RDONLY),
        os.open(os.devnull, os.O_RDONLY),
    )
    try:
        yield model_utility_sandbox._launch(config, stdin, descriptors)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _run(root: Path, *, same_keys: bool = False) -> tuple[int, str]:
    producer = bytes(range(32))
    verifier = producer if same_keys else bytes(range(32, 64))
    producer_fd = _key_fd(root, "producer.key", producer)
    verifier_fd = _key_fd(root, "verifier.key", verifier)
    try:
        digest = materializer._materialize(root, producer_fd, verifier_fd, fixture=True)
    except materializer.AdapterAdmissionMaterializerError:
        return 2, ""
    return 0, digest


def _bundle(root: Path) -> consumer._Bundle:
    return consumer._Bundle.model_validate_json(
        (root / "adapter-admission-bundle.json").read_bytes()
    )


def test_dry_fixture_runs_two_distinct_process_invocations_and_consumer_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "formal"
    _prepare(root)

    status, digest = _run(root)

    assert status == 0
    assert digest.startswith("sha256:")
    assert (root / "adapter-admission-bundle.json").is_file()
    assert Path("/etc/faultloom") not in root.resolve().parents
    with pytest.raises(
        materializer.AdapterAdmissionMaterializerError,
        match="staging root",
    ):
        materializer.materialize_adapter_admission(
            staging_root=Path("/etc/faultloom/t40-formal-v1"),
            producer_key_fd=-1,
            verifier_key_fd=-1,
        )
    bundle = _bundle(root)
    assert bundle.evaluation.state.value == "fully_done"
    assert bundle.evaluation.evidence_source.value == "real_model"
    assert len(bundle.evaluation.case_outcomes) == 2
    assert bundle.evaluation.metrics.dispatched_oos == 0
    assert bundle.evaluation.metrics.escaped_oos == 0
    coverage = bundle.admission.payload.outcome_coverage
    assert len(coverage) == 2
    assert (
        coverage[0].producer_canonical_request_digest
        != coverage[1].producer_canonical_request_digest
    )
    assert (
        coverage[0].producer_parsed_response_digest != coverage[1].producer_parsed_response_digest
    )
    producer_records = (root / "adapter-admission-producer.sequence").read_text().splitlines()
    assert [json.loads(item)["sequence"] for item in producer_records] == [1, 2]
    assert bundle.producer.payload.sequence == 2
    assert [item.payload.allocation_id for item in bundle.producer_attestations] == [
        "adapter-reference-admission-1.producer.1",
        "adapter-reference-admission-1.producer.2",
    ]
    assert [item.payload.attestation.payload.sequence for item in bundle.producer_attestations] == [
        1,
        2,
    ]
    assert [item.payload.attestation.payload.status for item in bundle.producer_attestations] == [
        "accepted",
        "accepted",
    ]
    assert bundle.producer_attestations[1].payload.attestation == bundle.producer
    assert bundle.producer.payload.producer_key_id.startswith("ed25519:sha256:")
    assert bundle.verifier.payload.verifier_key_id.startswith("ed25519:sha256:")
    assert bundle.producer.payload.producer_key_id != bundle.verifier.payload.verifier_key_id

    @contextmanager
    def held(config: LocalModelProcessConfig, encoded: bytes):
        with _held_formal_launch(config, encoded) as launch:
            yield launch

    monkeypatch.setattr("faultloom.t40_formal_producer_binding.pinned_process_launch", held)
    formal_binding = materialize_formal_producer_binding(
        core_wheel_digest=bundle.producer.payload.core_wheel_digest,
        timeout_seconds=20,
        maximum_request_bytes=65_536,
        maximum_response_bytes=65_536,
    )
    assert bundle.producer.payload.profile_digest == formal_binding.producer_profile_digest
    monkeypatch.setattr(consumer, "_read_bundle", lambda: (bundle, digest))
    monkeypatch.setattr(
        consumer,
        "verified_formal_profile_bindings",
        lambda: (digest, bundle.staging_manifest_sha256),
    )
    registry, accepted_digest = consumer.admitted_registry(reference_registry())
    assert accepted_digest == digest
    assert registry.doctor("adapter.reference").state is AdapterAdmissionState.ADMITTED_CANDIDATE


def test_production_api_routes_only_to_the_explicit_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage = (tmp_path / "stage").resolve()
    calls: list[tuple[Path, int, int, bool]] = []

    def capture(root: Path, producer_fd: int, verifier_fd: int, *, fixture: bool) -> str:
        calls.append((root, producer_fd, verifier_fd, fixture))
        return "sha256:" + "11" * 32

    monkeypatch.setattr(materializer, "_materialize", capture)
    digest = materializer.materialize_adapter_admission(
        staging_root=stage,
        producer_key_fd=31,
        verifier_key_fd=32,
    )
    assert digest == "sha256:" + "11" * 32
    assert calls == [(stage, 31, 32, False)]
    with pytest.raises(materializer.AdapterAdmissionMaterializerError, match="staging root"):
        materializer.materialize_adapter_admission(
            staging_root=Path("/etc/faultloom/t40-formal-v1"),
            producer_key_fd=31,
            verifier_key_fd=32,
        )
    assert calls == [(stage, 31, 32, False)]


def test_signed_install_profile_binds_bundle_and_staging_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path, public, payload = _signed_install_profile(tmp_path)
    read_owned_file = install._read_owned_file

    def read_test_profile(path: Path, *, uid: int, gid: int) -> bytes:
        assert (uid, gid) == (0, 0)
        return read_owned_file(path, uid=os.geteuid(), gid=os.getegid())

    monkeypatch.setattr(install, "FORMAL_PROFILE_PATH", profile_path)
    monkeypatch.setattr(install, "_read_owned_file", read_test_profile)
    monkeypatch.setattr(
        install,
        "_INSTALLATION_AUTHORITY_PUBLIC_KEY",
        base64.b64encode(public).decode(),
    )
    monkeypatch.setattr(
        install,
        "_INSTALLATION_AUTHORITY_SHA256",
        hashlib.sha256(public).hexdigest(),
    )
    assert install.verified_formal_profile_bindings() == (
        payload["adapter_admission_bundle_sha256"],
        payload["staging_manifest_sha256"],
    )

    malformed = profile_path.read_bytes().replace(
        str(payload["adapter_admission_bundle_sha256"]).encode(), b"sha256:short"
    )
    profile_path.write_bytes(malformed)
    profile_path.chmod(0o600)
    with pytest.raises(install.T40FaultLoomInstallError):
        install.verified_formal_profile_bindings()


def test_materializer_and_verifier_independently_accept_exact_staging_tree(
    tmp_path: Path,
) -> None:
    _generation, spec = _staging_fixture(tmp_path)
    parent = materializer._validate_staging_manifest(
        spec,
        production=False,
        verify_import_origins=False,
    )
    child = verifier._validate_staging_manifest(
        verifier.VerifierInputSpec.model_validate(spec.model_dump(mode="python")),
        production=False,
        verify_import_origins=False,
    )
    assert child == (
        parent.manifest_sha256,
        parent.installed_tree_sha256,
        parent.core_wheel_digest,
    )
    assert parent.core_wheel_digest == materializer._digest_bytes(b"faultloom_wheel")


def test_ambient_materializer_and_verifier_origins_are_rejected(tmp_path: Path) -> None:
    _generation, spec = _staging_fixture(tmp_path)
    with pytest.raises(
        materializer.AdapterAdmissionMaterializerError,
        match="ambient import origin",
    ):
        materializer._validate_staging_manifest(spec, production=False)
    with pytest.raises(ValueError, match="ambient verifier import origin"):
        verifier._validate_staging_manifest(
            verifier.VerifierInputSpec.model_validate(spec.model_dump(mode="python")),
            production=False,
        )


@pytest.mark.parametrize(
    "mutation,match",
    [
        ("manifest_a_vs_b", "A-vs-B"),
        ("source_role", "contract"),
        ("installed_file", "file digest"),
        ("extra_file", "inventory"),
        ("unsafe_mode", "metadata is unsafe"),
        ("launcher", "launcher binding"),
    ],
)
def test_staging_substitution_is_rejected_before_model(
    tmp_path: Path, mutation: str, match: str
) -> None:
    generation, spec = _staging_fixture(tmp_path / mutation)
    if mutation == "manifest_a_vs_b":
        spec = spec.model_copy(update={"staging_manifest_sha256": "sha256:" + "00" * 32})
    elif mutation == "source_role":
        manifest_path = generation / "staging-manifest.json"
        document = json.loads(manifest_path.read_bytes())
        document["sources"][1]["role"] = "faultloom_wheel"
        raw = canonical_json_bytes(document)
        manifest_path.chmod(0o600)
        manifest_path.write_bytes(raw)
        manifest_path.chmod(0o400)
        spec = spec.model_copy(update={"staging_manifest_sha256": materializer._digest_bytes(raw)})
    elif mutation == "installed_file":
        installed = generation / "site-packages/fixture_pkg/module.py"
        installed.chmod(0o600)
        installed.write_bytes(b"VALUE = 2\n")
        installed.chmod(0o400)
    elif mutation == "extra_file":
        extra = generation / "site-packages/fixture_pkg/extra.py"
        extra.write_bytes(b"EXTRA = True\n")
        extra.chmod(0o400)
    elif mutation == "unsafe_mode":
        (generation / "site-packages/fixture_pkg/module.py").chmod(0o600)
    else:
        launcher = generation / "isolated-launcher"
        launcher.chmod(0o600)
        launcher.write_bytes(b"raise SystemExit(1)\n")
        launcher.chmod(0o400)
    with pytest.raises(materializer.AdapterAdmissionMaterializerError, match=match):
        materializer._validate_staging_manifest(
            spec,
            production=False,
            verify_import_origins=False,
        )
    with pytest.raises((OSError, ValueError), match=match):
        verifier._validate_staging_manifest(
            verifier.VerifierInputSpec.model_validate(spec.model_dump(mode="python")),
            production=False,
            verify_import_origins=False,
        )


def test_rejects_reuse_and_same_signing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "formal"
    _prepare(root)
    assert _run(root)[0] == 0
    assert _run(root)[0] == 2
    assert not list(root.glob(".*.partial"))

    other = tmp_path / "same-key"
    _prepare(other)
    monkeypatch.setattr(
        materializer,
        "ReferenceProcessClient",
        lambda *args, **kwargs: pytest.fail("adapter ran before distinct-key preflight"),
    )
    assert _run(other, same_keys=True)[0] == 2
    assert not (other / "adapter-admission-bundle.json").exists()
    assert not (other / "adapter-admission-producer.sequence").exists()


def test_existing_output_and_unsafe_key_fail_before_adapter_or_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "preflight"
    _prepare(root)
    output = root / "adapter-admission-bundle.json"
    output.write_bytes(b"occupied")
    output.chmod(0o600)
    producer_fd = _key_fd(root, "producer.key", bytes(range(32)))
    verifier_fd = _key_fd(root, "verifier.key", bytes(range(32, 64)))
    monkeypatch.setattr(
        materializer,
        "ReferenceProcessClient",
        lambda *args, **kwargs: pytest.fail("adapter ran before output preflight"),
    )
    with pytest.raises(
        materializer.AdapterAdmissionMaterializerError,
        match="already exists",
    ):
        materializer._materialize(root, producer_fd, verifier_fd, fixture=True)
    assert not (root / "adapter-admission-producer.sequence").exists()

    output.unlink()
    pipe_fd, pipe_writer = os.pipe()
    os.write(pipe_writer, bytes(range(32)))
    os.close(pipe_writer)
    verifier_fd = _key_fd(root, "verifier-2.key", bytes(range(32, 64)))
    with pytest.raises(
        materializer.AdapterAdmissionMaterializerError,
        match="metadata is unsafe",
    ):
        materializer._materialize(root, pipe_fd, verifier_fd, fixture=True)

    unsafe_root = tmp_path / "unsafe-root"
    _prepare(unsafe_root)
    unsafe_root.chmod(0o755)
    assert _run(unsafe_root)[0] == 2
    assert not (unsafe_root / "adapter-admission-producer.sequence").exists()


def test_consumer_rejects_forged_output_and_mismatched_replay_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "forged"
    _prepare(root)
    assert _run(root)[0] == 0
    bundle = _bundle(root)
    monkeypatch.setattr(
        consumer,
        "_read_bundle",
        lambda: (bundle, "sha256:" + "11" * 32),
    )
    monkeypatch.setattr(
        consumer,
        "verified_formal_profile_bindings",
        lambda: ("sha256:" + "22" * 32, bundle.staging_manifest_sha256),
    )
    with pytest.raises(consumer.T40FaultLoomAdmissionError, match="installed profile"):
        consumer.admitted_registry(reference_registry())
    forged_producer = bundle.producer.model_copy(
        update={
            "payload": bundle.producer.payload.model_copy(
                update={"output_digest": "sha256:" + "00" * 32}
            )
        }
    )
    forged_sequence = bundle.producer_attestations[0].model_copy(
        update={
            "payload": bundle.producer_attestations[0].payload.model_copy(
                update={"allocation_id": "adapter-reference-admission-1.producer.2"}
            )
        }
    )
    variants = (
        bundle.model_copy(update={"session_id": "wrong.session"}),
        bundle.model_copy(update={"evaluator_challenge": "fedcba9876543210" * 4}),
        bundle.model_copy(update={"minimum_producer_sequence": 3}),
        bundle.model_copy(update={"staging_manifest_sha256": "sha256:" + "00" * 32}),
        bundle.model_copy(update={"installed_tree_sha256": "sha256:" + "00" * 32}),
        bundle.model_copy(
            update={
                "producer_attestations": (
                    forged_sequence,
                    bundle.producer_attestations[1],
                )
            }
        ),
        bundle.model_copy(
            update={
                "producer_attestations": (
                    bundle.producer_attestations[0],
                    bundle.producer_attestations[0],
                )
            }
        ),
        bundle.model_copy(update={"producer": forged_producer}),
    )
    monkeypatch.setattr(
        consumer,
        "verified_formal_profile_bindings",
        lambda: ("sha256:" + "00" * 32, bundle.staging_manifest_sha256),
    )
    for forged in variants:
        monkeypatch.setattr(
            consumer,
            "_read_bundle",
            lambda value=forged: (value, "sha256:" + "00" * 32),
        )
        with pytest.raises((ValueError, consumer.T40FaultLoomAdmissionError)):
            consumer.admitted_registry(reference_registry())
    missing = bundle.model_dump(mode="json")
    del missing["producer_attestations"]
    with pytest.raises(ValueError):
        consumer._Bundle.model_validate(missing)


def test_nofollow_input_and_partial_output_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "symlink"
    root.mkdir()
    target = tmp_path / "target.json"
    target.write_bytes(canonical_json_bytes(_spec()))
    target.chmod(0o600)
    (root / "adapter-admission-input.json").symlink_to(target)
    assert _run(root)[0] == 2

    clean = tmp_path / "cleanup"
    _prepare(clean)

    def fail_link(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(materializer.os, "link", fail_link)
    assert _run(clean)[0] == 2
    assert not (clean / "adapter-admission-bundle.json").exists()
    assert not list(clean.glob(".*.partial"))


def test_independent_verifier_rejects_transcript_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "verifier-mismatch"
    _prepare(root)
    original = materializer._run_verifier_child

    def forge_runtime(
        root_fd: int,
        verifier_key_fd: int,
        request: materializer.VerifierRequest,
        timeout: int,
        *,
        fixture: bool,
        staging_binding: materializer._StagingBinding,
    ):
        baseline, treatment = request.invocations
        forged = request.model_copy(
            update={
                "invocations": (
                    baseline,
                    treatment.model_copy(
                        update={"transcript_evidence_digest": "sha256:" + "00" * 32}
                    ),
                )
            }
        )
        return original(
            root_fd,
            verifier_key_fd,
            forged,
            timeout,
            fixture=fixture,
            staging_binding=staging_binding,
        )

    monkeypatch.setattr(materializer, "_run_verifier_child", forge_runtime)
    assert _run(root)[0] == 2
    assert not (root / "adapter-admission-bundle.json").exists()


def test_production_verifier_launch_ignores_pythonpath_shadow(tmp_path: Path) -> None:
    shadow = tmp_path / "shadow"
    package = shadow / "faultloom"
    package.mkdir(parents=True)
    marker = tmp_path / "shadow-imported"
    leaked = tmp_path / "hostile-leaked"
    (package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n"
    )
    launcher = tmp_path / "isolated-launcher"
    launcher.write_text(
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(leaked)!r}).write_text('leaked') if 'HOSTILE' in os.environ else None\n"
        "import faultloom\n"
    )
    launcher.chmod(0o400)
    digest = "sha256:" + "11" * 32
    binding = materializer._StagingBinding(
        manifest_sha256=digest,
        installed_tree_sha256=digest,
        core_wheel_digest=digest,
        generation_root=tmp_path,
        site_root=tmp_path / "site-packages",
        launcher_path=launcher,
        launcher_argv_prefix=(
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            str(launcher),
        ),
    )
    command = materializer._verifier_command(
        ["--verifier-key-fd", "999999", "--public-key-only"],
        fixture=False,
        staging_binding=binding,
    )
    assert tuple(command[:10]) == binding.launcher_argv_prefix
    environment = materializer._child_environment(fixture=False)
    environment["PYTHONPATH"] = str(shadow)
    environment["HOSTILE"] = "must-not-cross-env-i"
    completed = subprocess.run(
        command,
        capture_output=True,
        env=environment,
        check=False,
    )
    assert completed.returncode != 0
    assert not marker.exists()
    assert not leaked.exists()


def test_input_rejects_caller_supplied_core_digest() -> None:
    supplied = _spec() | {"core_wheel_digest": "sha256:" + "00" * 32}
    with pytest.raises(
        materializer.AdapterAdmissionMaterializerError,
        match="malformed",
    ):
        materializer._parse_spec(canonical_json_bytes(supplied))


def test_cli_stdout_contains_no_private_key_material(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "formal"
    _prepare(root)
    producer_seed = bytes(range(32))
    verifier_seed = bytes(range(32, 64))
    producer_fd = _key_fd(root, "producer.key", producer_seed)
    verifier_fd = _key_fd(root, "verifier.key", verifier_seed)

    assert (
        materializer.main(
            [
                "--dry-fixture-root",
                str(root),
                "--producer-key-fd",
                str(producer_fd),
                "--verifier-key-fd",
                str(verifier_fd),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["mode"] == "dry_fixture"
    assert producer_seed.hex() not in captured.out
    assert verifier_seed.hex() not in captured.out
