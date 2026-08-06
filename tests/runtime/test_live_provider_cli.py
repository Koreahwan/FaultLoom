from __future__ import annotations

import json
import socket
from argparse import Namespace
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from faultloom.automation.provider_contract import (
    MODEL_TURN_WIRE_NAME,
    model_turn_provider_tool_spec,
)
from faultloom.egress import EgressPlane
from faultloom.live_provider_cli import (
    LiveProviderTurnDependencies,
    LiveProviderTurnError,
    ProviderRuntimeConfig,
    run_live_provider_turn,
    sign_provider_runtime_config_file,
    sign_provider_runtime_config_value,
)
from faultloom.provider import (
    MetadataProvenance,
    MetadataSourceKind,
    OpenAICompatibleEndpointConfig,
    OpenAICompatibleHttpResponse,
    ProviderModelProfile,
    ProviderObservedMetadata,
    provider_tool_schema_digest,
)
from faultloom_protocol import (
    AuthoritySigner,
    ScopeEpoch,
    sign_authority_grant,
    sign_scope_epoch,
)

from tests.protocol.factories import NOW
from tests.runtime.provider_test_models import digest
from tests.runtime.test_authorized_automation import (
    DISCLOSURE_SIGNER,
    _request,  # pyright: ignore[reportPrivateUsage]
)
from tests.runtime.test_automation_provider_runner import (
    _base_intent,  # pyright: ignore[reportPrivateUsage]
    _model_turn_arguments,  # pyright: ignore[reportPrivateUsage]
)

AUTHORITY = AuthoritySigner.from_private_bytes(bytes.fromhex("11" * 32))
RECONCILIATION = AuthoritySigner.from_private_bytes(bytes.fromhex("22" * 32))
PROXY = bytes.fromhex("33" * 32)
SECRET = "provider-secret-must-not-be-persisted"


@dataclass
class FakePinnedHttp:
    calls: list[object] = field(default_factory=list)
    identity: str = "test.pinned-provider-http.v1"

    def dispatch(
        self,
        request: object,
        *,
        path: str,
        headers: dict[str, str],
        body: bytes,
        maximum_response_bytes: int,
    ) -> OpenAICompatibleHttpResponse:
        self.calls.append((request, path, headers, body, maximum_response_bytes))
        arguments = json.loads(_model_turn_arguments())
        return OpenAICompatibleHttpResponse(
            status=200,
            body=json.dumps(
                {
                    "model": "frontier-2030-01-01",
                    "choices": [{"message": {"tool_calls": [{
                        "id": "call_model_turn_1",
                        "type": "function",
                        "function": {
                            "name": MODEL_TURN_WIRE_NAME,
                            "arguments": json.dumps(arguments, separators=(",", ":")),
                        },
                    }]}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )


def _write(path: Path, value: object, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(value, "model_dump_json"):
        raw = value.model_dump_json().encode("utf-8") + b"\n"
    elif isinstance(value, bytes):
        raw = value.hex().encode("ascii") + b"\n"
    else:
        raw = json.dumps(value).encode("utf-8") + b"\n"
    path.write_bytes(raw)
    path.chmod(mode)


def _profile(request, *, provider_id: str = "provider.test", model: str = "frontier-2030-01-01", data_policy: str | None = None) -> ProviderModelProfile:
    tool = model_turn_provider_tool_spec()
    policy = data_policy or request.authority_grant.provider_policy.data_policy_id
    provenance = MetadataProvenance(
        schema_version="0.1.0",
        source_kind=MetadataSourceKind.PINNED_REGISTRY,
        source_id="provider-metadata-registry",
        evidence_digest=digest("provider-metadata"),
        observed_at=NOW,
        exact=True,
    )
    return ProviderModelProfile(
        profile_id="profile.operator",
        provider_id=provider_id,
        endpoint_id="endpoint.operator",
        requested_alias="frontier",
        exact_snapshot=model,
        runtime_version="runtime-1",
        tokenizer_id="tokenizer-1",
        tokenizer_version="v1",
        context_window=32_768,
        prompt_overhead_tokens=64,
        maximum_input_tokens=20_000,
        maximum_output_tokens=1_024,
        maximum_request_bytes=65_536,
        maximum_response_bytes=65_536,
        input_cost_per_million_microunits=1,
        output_cost_per_million_microunits=1,
        compatibility_group="openai-compatible",
        capability_digest=digest("capabilities"),
        tool_schema_digest=provider_tool_schema_digest((tool,)),
        policy_ref="provider-policy-v1",
        data_policy_id=policy,
        data_consent_ref="consent-receipt-v1",
        metadata_exact=True,
        metadata_provenance=provenance,
    )


def _config(request, intent, *, provider_id: str = "provider.test", model: str = "frontier-2030-01-01", data_policy: str | None = None, credential_mismatch: bool = False) -> ProviderRuntimeConfig:
    profile = _profile(request, provider_id=provider_id, model=model, data_policy=data_policy)
    observed = ProviderObservedMetadata(
        schema_version="0.1.0",
        provider_id=provider_id,
        actual_snapshot=model,
        runtime_version=profile.runtime_version,
        tokenizer_id=profile.tokenizer_id,
        tokenizer_version=profile.tokenizer_version,
        context_window=profile.context_window,
        snapshot_exact=True,
        runtime_exact=True,
        tokenizer_exact=True,
        context_window_exact=True,
        provenance=profile.metadata_provenance,
    )
    credential_ref = intent.credential_ref
    if credential_mismatch:
        credential_ref = credential_ref.model_copy(update={"uri": "secret://engagement/other"})
    endpoint = OpenAICompatibleEndpointConfig(
        endpoint_id=profile.endpoint_id,
        provider_id=provider_id,
        base_url="https://provider.example.com/v1",
        model=model,
        credential_ref=credential_ref,
        metadata=observed,
    )
    return ProviderRuntimeConfig(
        endpoint=endpoint,
        profile=profile,
        destination={
            "plane": EgressPlane.MODEL_PROVIDER,
            "origin": endpoint.origin,
            "addresses": ("8.8.8.8",),
        },
        credential_environment_variable="BOUND_PROVIDER_KEY",
    )


def _fixture(tmp_path: Path, *, config_changes: dict[str, object] | None = None, epoch: int = 7, tamper_authority: bool = False, with_secret: bool = True):
    request = _request()
    request = request.model_copy(
        update={
            "authority_grant": request.authority_grant.model_copy(
                update={
                    "budget": request.authority_grant.budget.model_copy(
                        update={"max_request_bytes": 65_536}
                    )
                }
            )
        }
    )
    intent = _base_intent(request).model_copy(update={
        "profile_id": "profile.operator",
        "scope_epoch": 7,
        "policy_ref": "provider-policy-v1",
        "data_consent_ref": "consent-receipt-v1",
        "credential_ref": _base_intent(request).credential_ref.model_copy(
            update={"purpose": "model-provider:provider.test"}
        ),
    })
    config = _config(request, intent, **(config_changes or {}))
    signed_authority = sign_authority_grant(request.authority_grant, AUTHORITY, signed_at=NOW)
    signed_config = sign_provider_runtime_config_value(
        config,
        signed_authority,
        AUTHORITY,
    )
    if tamper_authority:
        signed_authority = signed_authority.model_copy(update={
            "signature": signed_authority.signature.model_copy(update={"signature": "tampered"})
        })
    signed_epoch = sign_scope_epoch(
        ScopeEpoch(
            schema_version="0.1.0",
            grant_id=request.authority_grant.grant_id,
            epoch=epoch,
            issued_at=NOW,
            expires_at=request.authority_grant.expires_at,
            revoked=False,
        ),
        AUTHORITY,
        signed_at=NOW,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {
        "request": tmp_path / "request.json",
        "runtime_config": tmp_path / "runtime.json",
        "base_intent": tmp_path / "intent.json",
        "scope_epoch": tmp_path / "epoch.json",
        "trusted_key": tmp_path / "authority-public.json",
        "reconciliation_key": tmp_path / "reconciliation-public.json",
        "trusted_disclosure_key": tmp_path / "disclosure-public.json",
        "egress_state_key": tmp_path / "egress.key",
        "provider_state_key": tmp_path / "provider.key",
        "proxy_attestation_key": tmp_path / "proxy.key",
    }
    _write(workspace / "authority.json", signed_authority)
    _write(files["request"], request)
    _write(files["runtime_config"], signed_config)
    _write(files["base_intent"], intent)
    _write(files["scope_epoch"], signed_epoch)
    _write(files["trusted_key"], AUTHORITY.public_key_record)
    _write(files["reconciliation_key"], RECONCILIATION.public_key_record)
    _write(files["trusted_disclosure_key"], DISCLOSURE_SIGNER.public_key_record)
    _write(files["egress_state_key"], bytes.fromhex("44" * 32))
    _write(files["provider_state_key"], bytes.fromhex("55" * 32))
    _write(files["proxy_attestation_key"], PROXY)
    args = Namespace(
        workspace=workspace,
        minimum_grant_version=1,
        runtime_dir=tmp_path / "runtime",
        **files,
    )
    args.trusted_disclosure_key = [files["trusted_disclosure_key"]]
    http = FakePinnedHttp()
    emitted: list[object] = []
    deps = LiveProviderTurnDependencies(
        verify_workspace=lambda _workspace, _key: (
            {"run_id": request.observations.run_id},
            request.authority_grant,
            request.authority_grant.targets[0],
            NOW,
        ),
        capture_file=lambda path: path.read_bytes(),
        emit_json=emitted.append,
        environment={"BOUND_PROVIDER_KEY": SECRET} if with_secret else {},
        http_port=http,
    )
    return args, deps, http, emitted


def test_provider_turn_is_candidate_only_secret_free_and_durable_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, deps, http, emitted = _fixture(tmp_path)
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("target socket")))

    assert run_live_provider_turn(args, dependencies=deps) == 0
    assert len(http.calls) == 1
    output = emitted[0]
    assert isinstance(output, dict)
    assert output["provider_dispatch"] is True
    assert output["target_dispatch"] is False
    assert output["independent_verification"] is False
    assert output["automatic_submission"] is False
    assert (args.runtime_dir / "checkpoints" / "egress.json").is_file()
    assert (args.runtime_dir / "checkpoints" / "provider.json").is_file()
    persisted = tuple(
        path
        for root in (args.workspace, args.runtime_dir)
        for path in root.rglob("*")
        if path.is_file()
    )
    assert SECRET.encode() not in b"".join(path.read_bytes() for path in persisted)

    with pytest.raises(LiveProviderTurnError):
        run_live_provider_turn(args, dependencies=deps)
    assert len(http.calls) == 1


@pytest.mark.parametrize(
    ("changes", "epoch", "tamper", "with_secret"),
    [
        ({"provider_id": "provider.outside"}, 7, False, True),
        ({"model": "frontier-outside"}, 7, False, True),
        ({"data_policy": "policy.outside"}, 7, False, True),
        ({"credential_mismatch": True}, 7, False, True),
        ({}, 8, False, True),
        ({}, 7, True, True),
        ({}, 7, False, False),
    ],
)
def test_provider_turn_mismatches_fail_before_provider_bytes(
    tmp_path: Path,
    changes: dict[str, object],
    epoch: int,
    tamper: bool,
    with_secret: bool,
) -> None:
    args, deps, http, _ = _fixture(
        tmp_path,
        config_changes=changes,
        epoch=epoch,
        tamper_authority=tamper,
        with_secret=with_secret,
    )
    with pytest.raises(LiveProviderTurnError):
        run_live_provider_turn(args, dependencies=deps)
    assert http.calls == []


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ((), "credential_environment_variable", "ATTACKER_PROVIDER_KEY"),
        (("endpoint",), "base_url", "https://attacker.example.com/v1"),
        (("destination",), "addresses", ["1.1.1.1"]),
    ],
)
def test_provider_turn_rejects_unsigned_runtime_config_tampering_before_environment_or_bytes(
    tmp_path: Path,
    section: tuple[str, ...],
    field: str,
    replacement: object,
) -> None:
    args, deps, http, _ = _fixture(tmp_path)
    document = json.loads(args.runtime_config.read_text("utf-8"))
    target = document["payload"]
    for name in section:
        target = target[name]
    target[field] = replacement
    args.runtime_config.write_text(json.dumps(document), encoding="utf-8")

    class EnvironmentMustNotBeRead(dict[str, str]):
        def get(self, key: str, default: str | None = None) -> str | None:
            raise AssertionError(f"environment read before signed config verification: {key}")

    dependencies = replace(deps, environment=EnvironmentMustNotBeRead())
    with pytest.raises(
        LiveProviderTurnError,
        match="payload digest mismatch|signature verification failed",
    ):
        run_live_provider_turn(args, dependencies=dependencies)
    assert http.calls == []


def test_sign_provider_config_command_writes_verifiable_envelope(tmp_path: Path) -> None:
    request = _request()
    config = _config(request, _base_intent(request).model_copy(update={
        "credential_ref": _base_intent(request).credential_ref.model_copy(
            update={"purpose": "model-provider:provider.test"}
        )
    }))
    authority = sign_authority_grant(request.authority_grant, AUTHORITY, signed_at=NOW)
    config_path = tmp_path / "raw-config.json"
    authority_path = tmp_path / "authority.json"
    private_key_path = tmp_path / "authority.key"
    output_path = tmp_path / "signed-config.json"
    _write(config_path, config)
    _write(authority_path, authority)
    _write(private_key_path, bytes.fromhex("11" * 32))
    emitted: list[object] = []

    assert sign_provider_runtime_config_file(
        Namespace(
            config=config_path,
            authority=authority_path,
            private_key=private_key_path,
            out=output_path,
        ),
        capture_file=lambda path: path.read_bytes(),
        write_new_file=lambda path, content: path.write_bytes(content),
        emit_json=emitted.append,
    ) == 0
    signed = json.loads(output_path.read_text("utf-8"))
    assert signed["grant_id"] == request.authority_grant.grant_id
    assert signed["issuer_key_id"] == AUTHORITY.key_id
    assert emitted and isinstance(emitted[0], dict)

    wrong_private_key = tmp_path / "wrong-authority.key"
    wrong_output = tmp_path / "wrong-signed-config.json"
    _write(wrong_private_key, bytes.fromhex("12" * 32))
    with pytest.raises(LiveProviderTurnError, match="does not match"):
        sign_provider_runtime_config_file(
            Namespace(
                config=config_path,
                authority=authority_path,
                private_key=wrong_private_key,
                out=wrong_output,
            ),
            capture_file=lambda path: path.read_bytes(),
            write_new_file=lambda path, content: path.write_bytes(content),
            emit_json=emitted.append,
        )
    assert not wrong_output.exists()


@pytest.mark.parametrize("symlink_component", ["root", "checkpoints"])
def test_provider_turn_rejects_runtime_symlink_before_provider_bytes(
    tmp_path: Path,
    symlink_component: str,
) -> None:
    args, deps, http, _ = _fixture(tmp_path)
    linked_directory = tmp_path / "linked-runtime"
    linked_directory.mkdir(mode=0o700)
    if symlink_component == "root":
        args.runtime_dir.symlink_to(linked_directory, target_is_directory=True)
    else:
        args.runtime_dir.mkdir(mode=0o700)
        (args.runtime_dir / "checkpoints").symlink_to(
            linked_directory,
            target_is_directory=True,
        )

    with pytest.raises(LiveProviderTurnError, match="not a symlink"):
        run_live_provider_turn(args, dependencies=deps)
    assert http.calls == []


def test_provider_turn_parser_is_wired() -> None:
    from faultloom.cli import build_parser

    with pytest.raises(SystemExit) as raised:
        build_parser().parse_args(["automation", "provider-turn", "--help"])
    assert raised.value.code == 0
