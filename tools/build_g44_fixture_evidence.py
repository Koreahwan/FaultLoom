#!/usr/bin/env python3
"""Build inert G44 fixture data with digests of operator-selected local artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packs" / "web3" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "protocol" / "src"))

from faultloom_web3 import web_llm_web3_fixture_manifest  # noqa: E402
from labs.web_llm_web3 import OwnedWebLlmWeb3Fixture, SyntheticIdentities  # noqa: E402


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _canonical_time(value: str, label: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{label} must be YYYY-MM-DDTHH:MM:SSZ") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError(f"{label} must be canonical UTC time")
    return value


def _expected_path(path: Path, expected: str) -> Path:
    resolved = path.resolve()
    if resolved != (ROOT / expected).resolve():
        raise ValueError(f"artifact path must be exactly {expected}")
    return resolved


def _signed_provenance(
    *,
    private_key_path: Path,
    artifacts: tuple[tuple[str, str, Path], ...],
    created_at: str,
    expires_at: str,
) -> tuple[dict[str, object], bytes]:
    loaded = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("provenance private key must be an Ed25519 PEM key")
    artifact_manifest = {
        "artifacts": [
            {"path": relative_path, "role": role, "sha256": _digest(path)}
            for role, relative_path, path in artifacts
        ],
        "created_at": _canonical_time(created_at, "created_at"),
        "expires_at": _canonical_time(expires_at, "expires_at"),
        "goal_ids": ["G42-v0.2-depth-and-advanced-web", "G44-v0.3-web3"],
        "run_id": "run.g44.primary",
        "schema_version": "faultloom.g44.artifact-provenance.v1",
        "versions": {
            "core": "0.1.0-candidate",
            "g42": "0.2.0-candidate",
            "web3": "0.3.0-candidate",
        },
    }
    public_bytes = loaded.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = loaded.sign(_canonical_bytes(artifact_manifest))
    provenance: dict[str, object] = {
        "manifest": artifact_manifest,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "ed25519:sha256:" + hashlib.sha256(public_bytes).hexdigest(),
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        },
    }
    public_pem = loaded.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return provenance, public_pem


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-artifact", type=Path, required=True)
    parser.add_argument("--g42-artifact", type=Path, required=True)
    parser.add_argument("--pack-adapter-artifact", type=Path, required=True)
    parser.add_argument("--provenance-private-key", type=Path, required=True)
    parser.add_argument("--provenance-public-key-output", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    core_artifact = _expected_path(
        args.core_artifact, "packages/protocol/src/faultloom_protocol/models.py"
    )
    g42_artifact = _expected_path(
        args.g42_artifact, "packages/runtime/src/faultloom/semantic_depth.py"
    )
    web3_artifact = _expected_path(
        args.pack_adapter_artifact, "packs/web3/src/faultloom_web3/fixture.py"
    )
    artifact_provenance, public_pem = _signed_provenance(
        private_key_path=args.provenance_private_key,
        artifacts=(
            ("core", "packages/protocol/src/faultloom_protocol/models.py", core_artifact),
            ("g42", "packages/runtime/src/faultloom/semantic_depth.py", g42_artifact),
            ("web3", "packs/web3/src/faultloom_web3/fixture.py", web3_artifact),
        ),
        created_at=args.created_at,
        expires_at=args.expires_at,
    )
    identities = SyntheticIdentities(
        web_identity_id="synthetic.operator.web",
        model_identity_id="synthetic.operator.model",
        mcp_identity_id="synthetic.operator.mcp",
        web3_identity_id="synthetic.operator.web3",
    )
    fixture = OwnedWebLlmWeb3Fixture(identities)
    manifest = web_llm_web3_fixture_manifest(
        core_artifact_digest=_digest(core_artifact),
        g42_artifact_digest=_digest(g42_artifact),
        pack_adapter_digest=_digest(web3_artifact),
        expected_semantic_signatures=tuple(edge.semantic_signature for edge in fixture.edges),
    )
    bundle = fixture.evidence_bundle(manifest, artifact_provenance=artifact_provenance)
    args.provenance_public_key_output.parent.mkdir(parents=True, exist_ok=True)
    args.provenance_public_key_output.write_bytes(public_pem)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
