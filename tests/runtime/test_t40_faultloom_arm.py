from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import traceback
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom import t40_faultloom_arm as arm
from faultloom import t40_faultloom_install as install
from faultloom import t40_real_arm_protocol as protocol
from faultloom import t40_thin_frontier_arm as thin
from faultloom import t40_web_pack_process as web_process
from faultloom.model_utility_attestation_state import MonotonicAttestationState
from faultloom.model_utility_attestor import AttestedModelUtilityExchange
from faultloom.model_utility_process import BoundedProcessLaunch, BoundedProcessResult
from faultloom.model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
    FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
    LocalModelProcessResponse,
)
from faultloom.research import ResearchBinding
from faultloom.t40_arm_runtime import T40ArmPolicy, T40ArmRequest, T40ResourceBudget, T40RunKey
from faultloom.t40_real_arm_protocol import verify_real_arm_response
from faultloom_protocol import AuthoritySigner, canonical_json_bytes
from faultloom_sdk import (
    NormalizeObservationRequest,
    ReferenceProcessClient,
    UtilityDecision,
    reference_registry,
)
from faultloom_web import t40_worker

from labs.patch_variant import load_patch_variant_manifest
from labs.patch_variant.fixture import _build_request as build_patch_request
from labs.web_api import web_api_fixture
from tests.runtime.test_context import (
    DEFAULT_RETRIEVAL_KEY,
    VERIFY_AT,
    context_state,
    provider,
    scope_anchor,
)
from tests.runtime.test_semantic_depth import _chain, _config
from tests.runtime.test_specialist_merge import _proposal
from tests.runtime.test_specialist_merge import _request as merge_request
from tests.runtime.test_t40_thin_frontier_arm import _producer_receipt
from tests.runtime.test_tool_planner import (
    _admitted,
    _candidate,
    _grant,
    _hypothesis,
)
from tests.runtime.test_tool_planner import (
    _budget as planning_budget,
)


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _policy(*, maximum_response_bytes: int = 65_536) -> T40ArmPolicy:
    return T40ArmPolicy(
        model_snapshot_digest=FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
        model_runtime_digest=FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
        tool_schema_digest=_digest(b"tools"),
        gateway_policy_digest=_digest(b"gateway"),
        safety_policy_digest=_digest(b"safety"),
        generation_config_digest=_digest(b"generation"),
        allowed_tools=("lab.http.get",),
        budget=T40ResourceBudget(
            maximum_input_tokens=1024,
            maximum_output_tokens=256,
            maximum_model_calls=1,
            maximum_tool_dispatches=1,
            timeout_seconds=30,
            cpu_seconds=30,
            maximum_address_space_bytes=2_147_483_648,
            maximum_response_bytes=maximum_response_bytes,
        ),
    )


def _private_input() -> str:
    proposal = _proposal()
    manifest = load_patch_variant_manifest()
    private = arm.T40FaultLoomPrivateInput(
        schema_version="faultloom.t40-private-input.v1",
        context=arm._ContextInput(
            state=context_state(),
            provider=provider(),
            scope_anchors=(scope_anchor(),),
            retrieval_binding_key_hex=DEFAULT_RETRIEVAL_KEY.hex(),
            live=False,
            verification_time=VERIFY_AT,
        ),
        specialist=arm._SpecialistInput(
            binding=ResearchBinding(run_id="run.1", researcher_id="researcher.1"),
            proposal=proposal,
            merge_request=merge_request(proposal),
        ),
        planner=arm._PlannerInput(
            hypothesis=_hypothesis(),
            grant=_grant(),
            budget=planning_budget(),
            candidates=(_candidate("faultloom", gain=7000, cost=10),),
        ),
        semantic_graph=_chain(4).document(),
        semantic_config=_config(4).document(),
        patch_variant=build_patch_request(manifest, manifest.case("fixture.vulnerable")),
        web=web_api_fixture().positive,
    )
    return canonical_json_bytes(private.model_dump(mode="json")).decode("ascii")


def _request(policy: T40ArmPolicy, *, run_key: T40RunKey = "control") -> T40ArmRequest:
    private = _private_input()
    return T40ArmRequest(
        request_id=f"formal.faultloom.{run_key.replace('.', '-')}",
        arm_id="faultloom",
        run_key=run_key,
        arm_runtime_digest=arm.faultloom_implementation_digest(),
        case_digest=_digest(b"case"),
        private_input_digest=_digest(private.encode()),
        policy_digest=policy.policy_digest,
        model_snapshot_digest=policy.model_snapshot_digest,
        model_runtime_digest=policy.model_runtime_digest,
        tool_schema_digest=policy.tool_schema_digest,
        gateway_policy_digest=policy.gateway_policy_digest,
        safety_policy_digest=policy.safety_policy_digest,
        generation_config_digest=policy.generation_config_digest,
        budget_digest=policy.budget_digest,
        requested_tools=(),
        private_input=private,
        session_id="formal.faultloom.session.1",
        evaluator_challenge="0123456789abcdef" * 4,
        allocation_id="formal-faultloom-allocation-1",
        trusted_minimum_sequence=0,
        core_wheel_digest=_digest(b"core wheel"),
    )


def _forked_faultloom_worker(launch: BoundedProcessLaunch) -> BoundedProcessResult:
    child = os.fork()
    if child == 0:
        try:
            arm._serve_one(*launch.pass_fds)
        except Exception:  # noqa: BLE001 - the process harness maps failure to an exit code
            traceback.print_exc()
            os._exit(2)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    return BoundedProcessResult(returncode=os.waitstatus_to_exitcode(status), stdout=b"")


def _install_real_component_harness(
    monkeypatch: pytest.MonkeyPatch,
    adapter_receipt: Path,
) -> tuple[Ed25519PrivateKey, AuthoritySigner, list[BoundedProcessLaunch]]:
    launches: list[BoundedProcessLaunch] = []
    producer_key = Ed25519PrivateKey.generate()
    producer_signer = AuthoritySigner.from_private_bytes(producer_key.private_bytes_raw())
    original_normalize = ReferenceProcessClient.normalize

    def normalize_spy(
        self: ReferenceProcessClient, request: NormalizeObservationRequest
    ):
        result = original_normalize(self, request)
        adapter_receipt.write_text(result.normalized_observation.source_digest, encoding="ascii")
        return result

    def fixed_exchange(
        request: T40ArmRequest,
        policy: T40ArmPolicy,
        signer: AuthoritySigner,
        trace: tuple[protocol._T40ComponentTrace, ...],
        context: tuple[protocol._T40ComponentContext, ...],
    ) -> AttestedModelUtilityExchange:
        model_request = protocol._faultloom_model_request(
            request, policy, component_trace=trace, component_context=context
        )
        output = "bounded FaultLoom result"
        response = LocalModelProcessResponse(
            request_id=request.request_id,
            model_snapshot_digest=request.model_snapshot_digest,
            runtime_artifact_digest=request.model_runtime_digest,
            decision=UtilityDecision.INCONCLUSIVE,
            output=output,
            output_digest=_digest(output.encode()),
            raw_llama_stdout_digest=_digest(b"raw faultloom stdout"),
            input_tokens=31,
            output_tokens=5,
        )
        return AttestedModelUtilityExchange(
            response=response,
            producer_receipt=_producer_receipt(signer, request, policy, model_request, response),
        )

    def process_spy(launch: BoundedProcessLaunch) -> BoundedProcessResult:
        launches.append(launch)
        return _forked_faultloom_worker(launch)

    registry = reference_registry()
    monkeypatch.setattr(arm, "admitted_registry", lambda actual: (_admitted(actual), _digest(b"admission")))
    monkeypatch.setattr(arm, "_fixed_model_exchange", fixed_exchange)
    monkeypatch.setattr(arm, "run_bounded_process", process_spy)
    monkeypatch.setattr(arm, "_load_operator_producer_signing_key", producer_key.private_bytes_raw)
    monkeypatch.setattr(ReferenceProcessClient, "normalize", normalize_spy)
    monkeypatch.setattr(
        arm.WebPackProcessClient,
        "_fixed_exchange",
        lambda _self, encoded: t40_worker._serve(encoded),
    )
    assert t40_worker.__file__ is not None
    monkeypatch.setattr(web_process, "_worker_path", lambda: Path(t40_worker.__file__))
    assert registry.adapters[0].adapter_id == "adapter.reference"
    return producer_key, producer_signer, launches


@pytest.mark.parametrize(
    "run_key",
    (
        "control",
        "off.context_compiler",
        "off.specialist",
        "off.tool_planner",
        "off.t32",
        "off.t33",
        "off.t34",
        "off.t35",
        "off.adapters",
    ),
)
def test_public_faultloom_launcher_executes_actual_components_in_all_nine_modes(
    run_key: T40RunKey, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy()
    request = _request(policy, run_key=run_key)
    adapter_receipt = tmp_path / "adapter.receipt"
    producer_key, producer_signer, launches = _install_real_component_harness(
        monkeypatch, adapter_receipt
    )
    key = Ed25519PrivateKey.generate()

    encoded = arm._run_with_producer_key(
        request=request,
        policy=policy,
        signing_key=key.private_bytes_raw(),
        producer_key=producer_key.private_bytes_raw(),
    )
    response = verify_real_arm_response(
        encoded=encoded,
        request=request,
        policy=policy,
        public_key=key.public_key(),
        producer_trust_registry={producer_signer.key_id: producer_signer.public_key_record},
        minimum_producer_sequence=1,
        expected_session_id="formal.faultloom.session.1",
        expected_evaluator_challenge="0123456789abcdef" * 4,
    )

    assert response.run_key == run_key
    assert len(launches) == 1
    assert launches[0].argv[0] == "/usr/bin/bwrap"
    assert "--unshare-net" in launches[0].argv
    assert launches[0].argv.count(install.FORMAL_SITE_ROOT.as_posix()) == 3
    assert not any(".worktrees" in value for value in launches[0].argv)
    disabled = None if run_key == "control" else run_key.removeprefix("off.")
    statuses = {item.component: item.status for item in response.component_trace}
    if disabled is not None:
        assert statuses[disabled] == "disabled"
    assert response.component_use.tool_planner is (disabled != "tool_planner")
    assert response.component_use.adapters is (disabled != "adapters")
    assert adapter_receipt.exists() is (disabled != "adapters")
    if adapter_receipt.exists():
        assert adapter_receipt.read_text(encoding="ascii").startswith("sha256:")


def test_faultloom_run_key_vocabulary_is_closed_and_thin_defaults_control() -> None:
    policy = _policy()
    with pytest.raises(ValueError):
        T40ArmRequest.model_validate(
            {**_request(policy).model_dump(mode="python"), "run_key": "off.t32+off.t33"}
        )


def test_public_launcher_has_no_path_callable_or_producer_authority_seam() -> None:
    parameters = inspect.signature(arm.run_faultloom_arm).parameters
    assert tuple(parameters) == ("request", "policy", "signing_key")
    assert not {"path", "module", "callable", "producer_key", "bundle"}.intersection(parameters)
    assert "_run_with_producer_key" not in arm.__all__


def test_all_three_arms_share_one_contiguous_66_call_producer_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production_path = Path(
        "/var/lib/faultloom/t40-formal-v1/producer-attestation.sequence"
    )
    assert thin._ATTESTATION_STATE_PATH == production_path
    assert arm._ATTESTATION_STATE_PATH == production_path

    state_path = tmp_path / "producer-attestation.sequence"
    monkeypatch.setattr(thin, "_ATTESTATION_STATE_PATH", state_path)
    monkeypatch.setattr(arm, "_ATTESTATION_STATE_PATH", state_path)
    paths = {
        "legacy": state_path,
        "thin": thin._ATTESTATION_STATE_PATH,
        "faultloom": arm._ATTESTATION_STATE_PATH,
    }
    schedule = ("legacy", "thin", "faultloom") * 22
    observed: list[int] = []
    for ordinal, arm_name in enumerate(schedule, start=1):
        with MonotonicAttestationState(paths[arm_name]) as state:
            observed.append(
                state.allocate(
                    f"task9:{ordinal}:{arm_name}",
                    trusted_minimum_sequence=ordinal - 1,
                )
            )

    assert observed == list(range(1, 67))
    assert len(set(observed)) == 66


def _signed_envelope(payload: dict[str, object], key: Ed25519PrivateKey) -> bytes:
    payload_digest = _digest(canonical_json_bytes(payload))
    document = {"payload": payload, "payload_digest": payload_digest}
    signature = base64.urlsafe_b64encode(
        key.sign(canonical_json_bytes(document))
    ).decode().rstrip("=")
    return canonical_json_bytes({**document, "signature": signature})


def _installed_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, bytes]:
    site = tmp_path / "site-packages"
    site.mkdir(parents=True, mode=0o700)
    wheel_root = tmp_path / "wheels"
    wheel_root.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    files: dict[str, bytes] = {}
    wheels: dict[str, dict[str, object]] = {}
    for role, distribution in (
        ("faultloom_wheel", "faultloom"),
        ("protocol_wheel", "faultloom_protocol"),
        ("sdk_wheel", "faultloom_sdk"),
        ("web_wheel", "faultloom_web"),
    ):
        module_path = f"{distribution}/__init__.py"
        record_path = f"{distribution}-1.0.dist-info/RECORD"
        files[module_path] = f"NAME={distribution!r}\n".encode()
        files[record_path] = f"{module_path},sha256=test,{len(files[module_path])}\n".encode()
        wheel_bytes = f"{role}.wheel".encode()
        wheel_digest = _digest(wheel_bytes)
        wheel_path = wheel_root / install._WHEEL_FILES[role]
        wheel_path.write_bytes(wheel_bytes)
        wheel_path.chmod(0o400)
        wheels[role] = {
            "artifact_sha256": wheel_digest,
            "installed_files": [
                {"mode": 0o644, "path": module_path, "sha256": _digest(files[module_path])},
                {"mode": 0o644, "path": record_path, "sha256": _digest(files[record_path])},
            ],
        }
    for relative, content in files.items():
        path = site / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(content)
        path.chmod(0o644)
    staging_manifest_digest = _digest(b"staging-manifest")
    manifest_payload: dict[str, object] = {
        "schema": "faultloom.ops.t40-formal-python-install-manifest.v1",
        "site_root": {
            "gid": os.getgid(),
            "mode": 0o700,
            "path": install.FORMAL_SITE_ROOT.as_posix(),
            "uid": os.getuid(),
        },
        "wheels": wheels,
        "dependency_bundle_sha256": _digest(b"dependencies"),
        "staging_equivalence": {
            "installed_tree_sha256": _digest(b"installed-tree"),
            "staging_manifest_sha256": staging_manifest_digest,
        },
        "installed_tree": [
            {"mode": 0o644, "path": path, "sha256": _digest(content)}
            for path, content in sorted(files.items())
        ],
    }
    manifest = tmp_path / "python-install-manifest.json"
    manifest_raw = _signed_envelope(manifest_payload, key)
    manifest.write_bytes(manifest_raw)
    manifest.chmod(0o600)
    wheel_profile_digests: dict[str, str] = {}
    for manifest_role, profile_field in install._WHEEL_BINDINGS.items():
        artifact_digest = wheels[manifest_role]["artifact_sha256"]
        assert type(artifact_digest) is str
        wheel_profile_digests[profile_field] = artifact_digest
    profile_payload: dict[str, object] = {
        **{
            name: _digest(name.encode())
            for name in install._PROFILE_FIELDS
            if name.endswith("_sha256")
        },
        **{
            name: _digest(name.encode())
            for name in install._PROFILE_FIELDS
            if name.startswith("producer_") and name.endswith("_digest")
        },
        "schema": "faultloom.ops.t40-formal-install-profile.v1",
        "core_commit": "1" * 40,
        "core_tree": "2" * 40,
        "eval_commit": "3" * 40,
        "eval_tree": "4" * 40,
        "ops_commit": "5" * 40,
        "ops_tree": "6" * 40,
        "private_plan_commitment": _digest(b"private-plan"),
        "expected_calls": 66,
        "producer_sequence_start": 2,
        "lab_key_id": "lab-v1",
        "producer_key_id": "producer-v1",
        "legacy_arm_key_id": "legacy-v1",
        "thin_arm_key_id": "thin-v1",
        "faultloom_arm_key_id": "faultloom-v1",
        "verifier_key_id": "verifier-v1",
        "verifier_root_key_id": "root-v1",
        "argv": ["/usr/bin/bwrap", "--", "/usr/bin/python3.12"],
        "environment": {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        "execution": "one-shot-no-daemon",
        "cgroup": "required-v2",
        "cgroup_limits": {
            "cpu.max": "200000 100000",
            "memory.max": "4294967296",
            "memory.oom.group": "1",
            "pids.max": "128",
        },
        "python_argv": ["/usr/bin/python3.12", "-I", "-S", "-B"],
        "site_packages": install.FORMAL_SITE_ROOT.as_posix(),
        "network": "disabled",
        "python_install_manifest_sha256": _digest(manifest_raw),
        "dependency_bundle_sha256": manifest_payload["dependency_bundle_sha256"],
        "staging_manifest_sha256": staging_manifest_digest,
        **wheel_profile_digests,
    }
    profile = tmp_path / "profile.json"
    profile.write_bytes(_signed_envelope(profile_payload, key))
    profile.chmod(0o600)
    return site, profile, manifest, wheel_root, key.public_key().public_bytes_raw()


def test_public_launcher_rejects_live_checkout_before_loading_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    monkeypatch.setattr(
        arm,
        "_load_operator_producer_signing_key",
        lambda: pytest.fail("producer authority must not load"),
    )
    with pytest.raises(install.T40FaultLoomInstallError, match="metadata"):
        arm.run_faultloom_arm(
            request=_request(policy),
            policy=policy,
            signing_key=Ed25519PrivateKey.generate().private_bytes_raw(),
        )
    with pytest.raises(install.T40FaultLoomInstallError, match="outside"):
        install._validate_required_origins(Path("/definitely/not/the/live/checkout"))


@pytest.mark.parametrize("tamper", ("manifest", "record"))
def test_formal_install_rejects_signed_manifest_or_record_tamper(
    tamper: str, tmp_path: Path
) -> None:
    site, profile, manifest, wheel_root, trusted = _installed_fixture(tmp_path)
    install._validate_formal_installation_at(
        site_root=site,
        profile_path=profile,
        manifest_path=manifest,
        wheel_root=wheel_root,
        trusted_root=trusted,
        uid=os.getuid(),
        gid=os.getgid(),
    )
    if tamper == "manifest":
        document = json.loads(manifest.read_bytes())
        document["payload"]["dependency_bundle_sha256"] = _digest(b"tampered")
        manifest.write_bytes(canonical_json_bytes(document))
    else:
        record = next(site.glob("*.dist-info/RECORD"))
        record.write_text("tampered\n", encoding="ascii")
    with pytest.raises(install.T40FaultLoomInstallError, match="digest|signature"):
        install._validate_formal_installation_at(
            site_root=site,
            profile_path=profile,
            manifest_path=manifest,
            wheel_root=wheel_root,
            trusted_root=trusted,
            uid=os.getuid(),
            gid=os.getgid(),
        )


def test_worker_rejects_response_larger_than_shared_byte_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    request = _request(policy)
    monkeypatch.setattr(arm, "_execute_and_sign", lambda *_args: b"x" * 65_537)
    monkeypatch.setattr(arm, "_apply_resource_limits", lambda _budget: None)
    descriptors = (
        arm._seal_input("request", canonical_json_bytes(request.model_dump(mode="json"))),
        os.memfd_create("response", os.MFD_CLOEXEC),
        arm._seal_input("signing", b"a" * 32),
        arm._seal_input("producer", b"b" * 32),
        arm._seal_input("policy", canonical_json_bytes(policy.model_dump(mode="json"))),
    )
    try:
        with pytest.raises(arm.T40FaultLoomError, match="response exceeds"):
            arm._serve_one(*descriptors)
        assert os.fstat(descriptors[1]).st_size == 0
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _faultloom_signing_inputs(
    request: T40ArmRequest,
) -> tuple[
    tuple[protocol._T40ComponentTrace, ...],
    tuple[protocol._T40ComponentContext, ...],
    protocol.T40ComponentUse,
]:
    trace = tuple(
        protocol._T40ComponentTrace(
            component=component,
            status="used",
            trace_digest=_digest(component.encode()),
        )
        for component in protocol._FAULTLOOM_COMPONENTS
    )
    context = tuple(
        protocol._T40ComponentContext(component=component, summary="{}")
        for component in (
            "adapter_use",
            "context_compiler",
            "patch_variant",
            "semantic_depth",
            "specialist",
            "tool_planner",
            "web_pack",
        )
    )
    use = protocol.T40ComponentUse(
        context_compiler=True,
        specialist=True,
        tool_planner=True,
        t32=True,
        t33=True,
        t34=True,
        t35=True,
        adapters=True,
        semantic_depth=True,
        patch_variant=True,
        chain=True,
        identity_workflow=True,
        pack=True,
    )
    assert request.run_key == "control"
    return trace, context, use


@pytest.mark.parametrize("failure", ("tool", "input_tokens", "output_tokens"))
def test_faultloom_signer_rejects_unadmitted_tools_and_token_budget_exploits(
    failure: str,
) -> None:
    policy = _policy()
    request = _request(policy)
    if failure == "tool":
        request = request.model_copy(update={"requested_tools": ("unadmitted.exec",)})
    trace, context, use = _faultloom_signing_inputs(request)
    model_request = protocol._faultloom_model_request(
        request, policy, component_trace=trace, component_context=context
    )
    response = LocalModelProcessResponse(
        request_id=request.request_id,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.model_runtime_digest,
        decision=UtilityDecision.INCONCLUSIVE,
        output="bounded",
        output_digest=_digest(b"bounded"),
        raw_llama_stdout_digest=_digest(b"raw"),
        input_tokens=1025 if failure == "input_tokens" else 1,
        output_tokens=257 if failure == "output_tokens" else 1,
    )
    producer = AuthoritySigner.generate()
    receipt = _producer_receipt(producer, request, policy, model_request, response)
    with pytest.raises(protocol.T40ArmRuntimeError, match="admitted|token budget"):
        protocol._sign_faultloom_response(
            request=request,
            policy=policy,
            model_request=model_request,
            model_response=response,
            producer_receipt=receipt,
            component_trace=trace,
            component_context=context,
            component_use=use,
            runtime_implementation_digest=request.arm_runtime_digest,
            signing_key=Ed25519PrivateKey.generate(),
        )


def test_faultloom_verifier_rejects_signed_over_budget_response() -> None:
    policy = _policy()
    request = _request(policy)
    trace, context, use = _faultloom_signing_inputs(request)
    model_request = protocol._faultloom_model_request(
        request, policy, component_trace=trace, component_context=context
    )
    normal = LocalModelProcessResponse(
        request_id=request.request_id,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.model_runtime_digest,
        decision=UtilityDecision.INCONCLUSIVE,
        output="bounded",
        output_digest=_digest(b"bounded"),
        raw_llama_stdout_digest=_digest(b"raw"),
        input_tokens=1,
        output_tokens=1,
    )
    producer = AuthoritySigner.generate()
    key = Ed25519PrivateKey.generate()
    base = protocol._sign_faultloom_response(
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=normal,
        producer_receipt=_producer_receipt(producer, request, policy, model_request, normal),
        component_trace=trace,
        component_context=context,
        component_use=use,
        runtime_implementation_digest=request.arm_runtime_digest,
        signing_key=key,
    )
    over = normal.model_copy(update={"input_tokens": 1025})
    values = base.model_dump(mode="python")
    values["input_tokens"] = over.input_tokens
    values["model_response_digest"] = protocol._digest_bytes(
        protocol._canonical_local_model_bytes(over)
    )
    values["producer_receipt"] = _producer_receipt(
        producer, request, policy, model_request, over
    )
    values["observation_digest"] = protocol._digest_json(
        {
            "model_output_digest": over.output_digest,
            "model_response_digest": values["model_response_digest"],
            "request_digest": base.request_digest,
        }
    )
    unsigned = protocol.T40RealArmResponse.model_validate(
        {**values, "signature": "A" * 88}
    )
    values["signature"] = base64.b64encode(
        key.sign(canonical_json_bytes(protocol._unsigned_response(unsigned)))
    ).decode("ascii")
    encoded = canonical_json_bytes(
        protocol.T40RealArmResponse.model_validate(values).model_dump(mode="json")
    ) + b"\n"
    with pytest.raises(protocol.T40ArmRuntimeError, match="token budget"):
        verify_real_arm_response(
            encoded=encoded,
            request=request,
            policy=policy,
            public_key=key.public_key(),
            producer_trust_registry={producer.key_id: producer.public_key_record},
            minimum_producer_sequence=1,
            expected_session_id="formal.faultloom.session.1",
            expected_evaluator_challenge="0123456789abcdef" * 4,
        )
