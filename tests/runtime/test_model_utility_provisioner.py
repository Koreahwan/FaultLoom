from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools import provision_model_utility_profile as provisioner


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> provisioner.StagedProfile:
    values = {
        "bwrap": b"bwrap",
        "wrapper": b"wrapper",
        "bundle": b"bundle",
        "model": b"model",
    }
    for name, value in values.items():
        monkeypatch.setattr(provisioner, f"_{name.upper()}_DIGEST", _digest(value))
    monkeypatch.setattr(provisioner, "_MODEL_SIZE", len(values["model"]))
    monkeypatch.setattr(provisioner, "_BUNDLE_SIZE", len(values["bundle"]))
    model_card = b"Apache-2.0 staged model card\n"
    monkeypatch.setattr(provisioner, "_MODEL_CARD_DIGEST", _digest(model_card))
    monkeypatch.setattr(provisioner, "_MODEL_CARD_SIZE", len(model_card))
    monkeypatch.setattr(
        provisioner,
        "_copy_bundle_license",
        lambda _bundle, destination: destination.write_text("llama.cpp license\n"),
    )
    paths = {name: tmp_path / name for name in values}
    for name, value in values.items():
        paths[name].write_bytes(value)
    bundle_metadata = _write_json(
        tmp_path / "bundle.json",
        {
            "archive": "llama-b10107-bin-ubuntu-x64.tar.gz",
            "commit": provisioner._BUNDLE_COMMIT,
            "release": "b10107",
            "sha256": provisioner._BUNDLE_DIGEST,
            "size": provisioner._BUNDLE_SIZE,
        },
    )
    model_metadata = _write_json(
        tmp_path / "model.json",
        {
            "file": "smollm2-360m-instruct-q8_0.gguf",
            "repository": "HuggingFaceTB/SmolLM2-360M-Instruct-GGUF",
            "revision": provisioner._MODEL_REVISION,
            "sha256": provisioner._MODEL_DIGEST,
            "size": provisioner._MODEL_SIZE,
        },
    )
    license_path = tmp_path / "MODEL_CARD.md"
    license_path.write_bytes(model_card)
    return provisioner.StagedProfile(
        bwrap=paths["bwrap"],
        wrapper=paths["wrapper"],
        bundle=paths["bundle"],
        model=paths["model"],
        bundle_metadata=bundle_metadata,
        model_metadata=model_metadata,
        model_license=license_path,
    )


def test_provisioner_atomically_installs_exact_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = _staged(tmp_path, monkeypatch)
    parent = tmp_path / "opt" / "faultloom"
    parent.mkdir(parents=True)
    target = parent / "model-utility-v1"
    result = provisioner.provision_profile(
        staged, profile_root=target, enforce_root_owner=False
    )
    assert result == target
    assert (target / "bwrap").read_bytes() == b"bwrap"
    assert (target / "runtime").read_bytes() == b"wrapper"
    assert (target / "model.gguf").read_bytes() == b"model"
    assert (target / "llama-b10107-bin-ubuntu-x64.tar.gz").read_bytes() == b"bundle"
    assert json.loads((target / "config.json").read_bytes()) == {
        "maximum_request_bytes": 16_777_216,
        "maximum_response_bytes": 16_777_216,
        "profile": "faultloom_utility_v1",
        "timeout_seconds": 300,
    }
    assert not list(parent.glob(".model-utility-v1.stage-*"))


def test_provisioner_fails_closed_without_partial_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = _staged(tmp_path, monkeypatch)
    staged.model.write_bytes(b"substituted")
    parent = tmp_path / "opt" / "faultloom"
    parent.mkdir(parents=True)
    target = parent / "model-utility-v1"
    with pytest.raises(provisioner.ProvisionError, match="size mismatch"):
        provisioner.provision_profile(
            staged, profile_root=target, enforce_root_owner=False
        )
    assert not target.exists()
    assert not list(parent.glob(".model-utility-v1.stage-*"))


def test_provisioner_rejects_wrong_pinned_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = _staged(tmp_path, monkeypatch)
    document = json.loads(staged.model_metadata.read_text())
    document["revision"] = "0" * 40
    _write_json(staged.model_metadata, document)
    parent = tmp_path / "opt" / "faultloom"
    parent.mkdir(parents=True)
    with pytest.raises(provisioner.ProvisionError, match="does not match"):
        provisioner.provision_profile(
            staged,
            profile_root=parent / "model-utility-v1",
            enforce_root_owner=False,
        )
