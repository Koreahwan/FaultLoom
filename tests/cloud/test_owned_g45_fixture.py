from __future__ import annotations

import http.client
import json
import socket
import sys
import types
import urllib.request
from dataclasses import replace
from pathlib import Path
from typing import Literal, cast

import pytest

from faultloom.execution import GatewayDispatchCommand
from faultloom_cloud import (
    build_read_only_cloud_trust_action_plan,
    evaluate_owned_cloud_trust_fixture,
    load_cloud_trust_input_manifest,
    verify_owned_cloud_trust_fixture,
)
from labs.cloud_iam_oauth import LoopbackCloudTrustFixture


CloudCaseId = Literal[
    "iam-trust-mismatch",
    "oauth-redirect-mismatch",
    "iam-matched-negative",
    "oauth-matched-negative",
]


def test_g45_signed_digest_pinned_inputs_compile_an_inert_gateway_command() -> None:
    with LoopbackCloudTrustFixture() as fixture:
        result = evaluate_owned_cloud_trust_fixture(
            fixture, fixture.manifest, "iam-trust-mismatch"
        )
        fixture.assert_read_only_loopback()

    plan = result.action_plan
    command = plan.command
    assert type(command) is GatewayDispatchCommand
    assert plan.dispatch_performed is False
    assert plan.provider_api_used is False
    assert plan.credentials_present is False
    assert plan.candidate_only is True
    assert command.request.method == "GET"
    assert command.request.endpoint.hostname == "g45.fixture.invalid"
    assert command.request.endpoint.path == "/g45/cloud-iam-oauth/iam-trust-mismatch"
    assert command.identity.session_ref is None
    assert command.lease.grant_id == fixture.manifest.authority_grant_id
    assert command.lease.scope_epoch == fixture.manifest.scope_epoch
    assert command.lease.reservation.request_bytes == fixture.manifest.request_bytes
    assert command.lease.reservation.response_bytes == fixture.manifest.response_bytes
    assert command.lease.reservation.duration_seconds == fixture.manifest.duration_seconds
    assert result.verifier_receipt == evaluate_owned_cloud_trust_fixture(
        _StaticSource("iam-trust-mismatch", _body_for("iam-trust-mismatch")),
        fixture.manifest,
        "iam-trust-mismatch",
    ).verifier_receipt
    assert result.verifier_receipt.classification == "candidate_only"
    assert result.verifier_receipt.verified is False
    assert result.verifier_receipt.gateway_dispatch_performed is False
    assert result.verifier_receipt.provider_api_calls == 0
    assert result.verifier_receipt.credentials_present is False
    assert fixture.cleanup_proof().cleanup_complete is True


@pytest.mark.parametrize(
    "case_id",
    ("iam-matched-negative", "oauth-matched-negative"),
)
def test_g45_matched_negative_controls_remain_inert_and_unverified(
    case_id: CloudCaseId,
) -> None:
    with LoopbackCloudTrustFixture() as fixture:
        result = evaluate_owned_cloud_trust_fixture(fixture, fixture.manifest, case_id)

    assert result.run.evidence.classification == "matched_negative_control"
    assert result.run.evidence.candidate_reasons == ()
    assert result.run.verdict.classification == "negative_control"
    assert result.verifier_receipt.classification == "matched_negative_control"
    assert result.verifier_receipt.verified is False
    assert result.action_plan.dispatch_performed is False
    assert fixture.cleanup_proof().secret_material_found is False


def test_g45_rejects_tampered_signed_manifest_and_unpinned_projection(
    tmp_path: Path,
) -> None:
    manifest_path = Path(__file__).parents[2] / "labs" / "cloud_iam_oauth" / "manifest.g45.json"
    document = json.loads(manifest_path.read_text())
    document["payload"]["budget"]["request_bytes"] = 513
    tampered_path = tmp_path / "tampered-manifest.json"
    tampered_path.write_text(json.dumps(document))

    with pytest.raises(ValueError, match="digest"):
        _ = load_cloud_trust_input_manifest(tampered_path)

    with LoopbackCloudTrustFixture() as fixture:
        altered = _StaticSource(
            "iam-trust-mismatch",
            _body_for("iam-trust-mismatch").replace(b"false", b"true", 1),
        )
        with pytest.raises(ValueError, match="digest differs"):
            _ = evaluate_owned_cloud_trust_fixture(
                altered, fixture.manifest, "iam-trust-mismatch"
            )

    assert fixture.cleanup_proof().provider_api_calls == 0


def test_g45_rejects_any_non_owned_loopback_route_before_normalization() -> None:
    with LoopbackCloudTrustFixture() as fixture:
        wrong_route = _StaticSource(
            "iam-trust-mismatch",
            _body_for("iam-trust-mismatch"),
            url="https://provider.example/iam-trust-mismatch",
        )
        with pytest.raises(ValueError, match="exact loopback route"):
            _ = evaluate_owned_cloud_trust_fixture(
                wrong_route, fixture.manifest, "iam-trust-mismatch"
            )

    assert fixture.cleanup_proof().gateway_dispatches == 0


def test_g45_preparation_and_verification_are_data_only_with_runtime_egress_sentinels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with LoopbackCloudTrustFixture() as fixture:
        initial = evaluate_owned_cloud_trust_fixture(
            fixture, fixture.manifest, "iam-trust-mismatch"
        )
        manifest = fixture.manifest

    egress_calls: list[str] = []

    def blocked(name: str):
        def _blocked(*_args: object, **_kwargs: object) -> None:
            egress_calls.append(name)
            raise AssertionError(f"G45 preparation attempted {name}")

        return _blocked

    monkeypatch.setattr(socket, "create_connection", blocked("socket.create_connection"))
    monkeypatch.setattr(socket.socket, "connect", blocked("socket.socket.connect"))
    monkeypatch.setattr(http.client.HTTPConnection, "connect", blocked("http.connect"))
    monkeypatch.setattr(urllib.request, "urlopen", blocked("urllib.request.urlopen"))
    for module_name in ("boto3", "google.cloud", "azure.identity"):
        provider = types.ModuleType(module_name)
        setattr(provider, "client", blocked(f"{module_name}.client"))
        setattr(provider, "resource", blocked(f"{module_name}.resource"))
        monkeypatch.setitem(sys.modules, module_name, provider)

    plan = build_read_only_cloud_trust_action_plan(manifest, initial.run)
    receipt = verify_owned_cloud_trust_fixture(manifest, initial.run, plan)

    assert egress_calls == []
    assert type(plan.command) is GatewayDispatchCommand
    assert not hasattr(plan, "dispatch")
    assert not hasattr(plan.command, "dispatch")
    assert not hasattr(plan.command, "connect")
    assert _is_json_data(plan.command.model_dump(mode="json"))
    assert _is_json_data(receipt.__dict__)
    assert receipt == initial.verifier_receipt
    assert replace(
        manifest,
        source_digests=(
            ("iam-trust-mismatch", "sha256:" + "0" * 64),
            *manifest.source_digests[1:],
        ),
    ).input_digest != manifest.input_digest
    assert fixture.cleanup_proof().loopback_server_running is False


class _StaticSource:
    def __init__(self, case_id: str, body: bytes, *, url: str | None = None) -> None:
        self._case_id = case_id
        self._body = body
        self._url = url or f"http://127.0.0.1/{case_id}"

    def read(self, case_id: object) -> "_StaticSnapshot":
        assert case_id == self._case_id
        return _StaticSnapshot(url=self._url, body=self._body)


class _StaticSnapshot:
    def __init__(self, *, url: str, body: bytes) -> None:
        self.url = url
        self.body = body


def _body_for(case_id: str) -> bytes:
    with LoopbackCloudTrustFixture() as fixture:
        return fixture.read(cast(CloudCaseId, case_id)).body


def _is_json_data(value: object) -> bool:
    if value is None or type(value) in (bool, int, str):
        return True
    if isinstance(value, list):
        return all(_is_json_data(item) for item in value)
    if isinstance(value, dict):
        return all(type(key) is str and _is_json_data(item) for key, item in value.items())
    return False
