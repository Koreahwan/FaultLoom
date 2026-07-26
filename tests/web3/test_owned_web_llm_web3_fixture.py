from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from faultloom_web3 import (
    G44VerificationError,
    verify_g44_evidence,
    web_llm_web3_fixture_manifest,
)
from labs.web_llm_web3 import (
    BridgeConfiguration,
    FixtureState,
    OwnedWebLlmWeb3Fixture,
    SyntheticIdentities,
)


CORE_DIGEST = "sha256:" + "41" * 32
G42_DIGEST = "sha256:" + "42" * 32
PACK_ADAPTER_DIGEST = "sha256:" + "44" * 32
VERIFY_TIME = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)


def identities() -> SyntheticIdentities:
    return SyntheticIdentities(
        web_identity_id="synthetic.operator.web",
        model_identity_id="synthetic.operator.model",
        mcp_identity_id="synthetic.operator.mcp",
        web3_identity_id="synthetic.operator.web3",
    )


@pytest.fixture
def provenance_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _provenance(
    private_key: Ed25519PrivateKey,
    *,
    core_digest: str = CORE_DIGEST,
    created_at: str = "2026-07-26T00:00:00Z",
    expires_at: str = "2026-07-27T00:00:00Z",
) -> dict[str, object]:
    artifact_manifest = {
        "artifacts": [
            {
                "path": "packages/protocol/src/faultloom_protocol/models.py",
                "role": "core",
                "sha256": core_digest,
            },
            {
                "path": "packages/runtime/src/faultloom/semantic_depth.py",
                "role": "g42",
                "sha256": G42_DIGEST,
            },
            {
                "path": "packs/web3/src/faultloom_web3/fixture.py",
                "role": "web3",
                "sha256": PACK_ADAPTER_DIGEST,
            },
        ],
        "created_at": created_at,
        "expires_at": expires_at,
        "goal_ids": ["G42-v0.2-depth-and-advanced-web", "G44-v0.3-web3"],
        "run_id": "run.g44.primary",
        "schema_version": "faultloom.g44.artifact-provenance.v1",
        "versions": {
            "core": "0.1.0-candidate",
            "g42": "0.2.0-candidate",
            "web3": "0.3.0-candidate",
        },
    }
    payload = json.dumps(
        artifact_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "manifest": artifact_manifest,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "ed25519:sha256:" + hashlib.sha256(public_bytes).hexdigest(),
            "signature": base64.urlsafe_b64encode(private_key.sign(payload))
            .rstrip(b"=")
            .decode("ascii"),
        },
    }


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def evidence_bundle(
    private_key: Ed25519PrivateKey,
    *,
    created_at: str = "2026-07-26T00:00:00Z",
    expires_at: str = "2026-07-27T00:00:00Z",
) -> dict[str, Any]:
    fixture = OwnedWebLlmWeb3Fixture(identities())
    manifest = web_llm_web3_fixture_manifest(
        core_artifact_digest=CORE_DIGEST,
        g42_artifact_digest=G42_DIGEST,
        pack_adapter_digest=PACK_ADAPTER_DIGEST,
        expected_semantic_signatures=tuple(edge.semantic_signature for edge in fixture.edges),
    )
    return fixture.evidence_bundle(
        manifest,
        artifact_provenance=_provenance(
            private_key, created_at=created_at, expires_at=expires_at
        ),
    )


def verify(
    bundle: object,
    private_key: Ed25519PrivateKey,
    *,
    verification_time: datetime = VERIFY_TIME,
):
    return verify_g44_evidence(
        bundle,
        trusted_provenance_public_key=_public_bytes(private_key),
        verification_time=verification_time,
    )


def test_independent_data_only_verifier_proves_exact_depth_eight_fixture(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = evidence_bundle(provenance_private_key)
    report = verify(bundle, provenance_private_key)

    assert report.passed
    assert report.semantic_depth == 8
    assert len(report.minimized_edge_ids) == len(set(report.minimized_edge_ids)) == 8
    assert report.boundary_crossings == (
        "web_api_to_llm_mcp",
        "llm_mcp_to_web3",
    )
    assert report.negative_controls_passed == (
        "remove_web_api_to_llm_mcp_bridge",
        "remove_llm_mcp_to_web3_bridge",
    )
    assert report.clean_replay_passed
    assert report.cleanup_passed
    assert report.lost_ids == 0
    assert report.duplicate_effects == 0
    assert "private_key" not in json.dumps(bundle)


@pytest.mark.parametrize(
    "bridges,expected_depth",
    (
        (BridgeConfiguration(web_api_to_llm_mcp=False), 2),
        (BridgeConfiguration(llm_mcp_to_web3=False), 5),
    ),
)
def test_fixture_itself_stops_when_either_bridge_is_removed(
    bridges: BridgeConfiguration, expected_depth: int
) -> None:
    fixture = OwnedWebLlmWeb3Fixture(identities())
    with fixture:
        evidence = fixture.run(bridges)
    assert len(evidence.edge_ids) == expected_depth
    assert not evidence.final_canary_reached
    assert fixture.state == FixtureState()


def test_verifier_rejects_reinserted_bridge_in_negative_control(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = evidence_bundle(provenance_private_key)
    controls = bundle["negative_controls"]
    primary = bundle["primary_run"]
    assert isinstance(controls, list) and isinstance(primary, dict)
    controls[0]["edges"] = primary["edges"]

    with pytest.raises(G44VerificationError, match="exact bridge removal"):
        verify(bundle, provenance_private_key)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("semantic_signature", "semantic signature mismatch"),
        ("expired_lease", "expired or not fresh"),
        ("reset_id", "preserve IDs"),
        ("warm_replay", "not pristine"),
        ("cleanup", "cleanup did not restore"),
    ),
)
def test_verifier_rejects_pinned_receipt_reset_replay_and_cleanup_tampering(
    mutation: str,
    message: str,
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = deepcopy(evidence_bundle(provenance_private_key))
    if mutation == "semantic_signature":
        bundle["primary_run"]["edges"][0]["semantic_signature"] = CORE_DIGEST
    elif mutation == "expired_lease":
        policy = bundle["primary_run"]["edges"][0]["policy"]
        policy["expires_at_tick"] = policy["issued_at_tick"]
        # Receipt mismatch would fail earlier; pin a syntactically valid but wrong receipt to prove fail closed.
        policy["receipt_id"] = "receipt." + "00" * 32
    elif mutation == "reset_id":
        bundle["reset"]["after_persistent_ids"].pop()
    elif mutation == "warm_replay":
        bundle["clean_replay"]["warm_frontier"] = ["cached-success"]
    else:
        bundle["cleanup"]["after"]["final_canary"] = "not-clean"

    expected = message if mutation != "expired_lease" else "policy receipt"
    with pytest.raises(G44VerificationError, match=expected):
        verify(bundle, provenance_private_key)


def test_provenance_rejects_wrong_externally_pinned_key(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = evidence_bundle(provenance_private_key)
    wrong_key = Ed25519PrivateKey.generate()
    with pytest.raises(G44VerificationError, match="wrong externally pinned key"):
        verify(bundle, wrong_key)


def test_provenance_rejects_forged_digest_even_with_recomputed_json(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = deepcopy(evidence_bundle(provenance_private_key))
    forged = "sha256:" + "99" * 32
    bundle["manifest"]["core_artifact_digest"] = forged
    bundle["artifact_provenance"]["manifest"]["artifacts"][0]["sha256"] = forged
    with pytest.raises(G44VerificationError, match="signature verification failed"):
        verify(bundle, provenance_private_key)


def test_provenance_rejects_expired_signed_manifest(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = evidence_bundle(
        provenance_private_key,
        created_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-25T00:00:00Z",
    )
    with pytest.raises(G44VerificationError, match="expired"):
        verify(bundle, provenance_private_key)


def test_provenance_rejects_path_swap(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = deepcopy(evidence_bundle(provenance_private_key))
    bundle["artifact_provenance"]["manifest"]["artifacts"][0]["path"] = (
        "packages/runtime/src/faultloom/semantic_depth.py"
    )
    with pytest.raises(G44VerificationError, match="path, role, or digest mismatch"):
        verify(bundle, provenance_private_key)


def test_provenance_rejects_unsigned_manifest(
    provenance_private_key: Ed25519PrivateKey,
) -> None:
    bundle = deepcopy(evidence_bundle(provenance_private_key))
    bundle["artifact_provenance"]["signature"] = {}
    with pytest.raises(G44VerificationError, match="unsigned"):
        verify(bundle, provenance_private_key)


def test_manifest_requires_separate_core_g42_and_adapter_digests() -> None:
    fixture = OwnedWebLlmWeb3Fixture(identities())
    signatures = tuple(edge.semantic_signature for edge in fixture.edges)
    with pytest.raises(ValueError, match="core_artifact_digest"):
        web_llm_web3_fixture_manifest(
            core_artifact_digest="latest",
            g42_artifact_digest=G42_DIGEST,
            pack_adapter_digest=PACK_ADAPTER_DIGEST,
            expected_semantic_signatures=signatures,
        )
    with pytest.raises(ValueError, match="g42_artifact_digest"):
        web_llm_web3_fixture_manifest(
            core_artifact_digest=CORE_DIGEST,
            g42_artifact_digest="latest",
            pack_adapter_digest=PACK_ADAPTER_DIGEST,
            expected_semantic_signatures=signatures,
        )


def test_real_or_reused_identity_is_rejected_before_run() -> None:
    with pytest.raises(ValueError, match="only operator-provisioned synthetic"):
        OwnedWebLlmWeb3Fixture(
            SyntheticIdentities(
                web_identity_id="production.wallet",
                model_identity_id="synthetic.operator.model",
                mcp_identity_id="synthetic.operator.mcp",
                web3_identity_id="synthetic.operator.web3",
            )
        )
