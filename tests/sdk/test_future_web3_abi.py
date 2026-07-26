from __future__ import annotations

import sys
from pathlib import Path

from faultloom_protocol import PackManifest
from faultloom_sdk import ManifestRegistry


WEB3_PACK_SOURCE = Path(__file__).parents[2] / "packs" / "web3" / "src"
sys.path.insert(0, str(WEB3_PACK_SOURCE))

from faultloom_web3 import web3_pack_manifest


FIXTURE = Path(__file__).parent / "fixtures" / "future_web3_pack_manifest.json"


def test_web3_pack_uses_the_predeclared_public_abi() -> None:
    manifest = PackManifest.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    assert web3_pack_manifest() == manifest
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
