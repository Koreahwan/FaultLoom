from __future__ import annotations

from pathlib import Path

from faultloom_protocol import PackManifest
from faultloom_sdk import ManifestRegistry


FIXTURE = Path(__file__).parent / "fixtures" / "future_web3_pack_manifest.json"


def test_future_web3_pack_uses_public_abi_without_web3_implementation() -> None:
    manifest = PackManifest.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    registry = ManifestRegistry(
        known_capability_descriptors=manifest.capability_descriptors,
        known_action_compilers=manifest.action_compilers,
        known_observation_normalizers=manifest.observation_normalizers,
        known_hypothesis_providers=manifest.hypothesis_providers,
        known_verifier_descriptors=manifest.verifier_descriptors,
        known_evaluation_descriptors=manifest.evaluation_descriptors,
        known_adapter_capabilities={"web3.read_only_rpc"},
        available_gateway_features={"web3.simulation"},
    )
    registry.install_pack(manifest)

    assert registry.packs == (manifest,)
    assert not (Path(__file__).parents[2] / "packs" / "web3").exists()
