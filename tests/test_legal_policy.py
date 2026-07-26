from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APACHE_2_DIGEST = bytes(
    (
        81, 71, 107, 27, 55, 154, 189, 180, 227, 195, 30, 47, 78, 175, 188, 98,
        140, 206, 239, 8, 222, 68, 149, 132, 39, 27, 78, 229, 223, 220, 167, 118,
    )
)
LEGACY_MIT_GRANT_DIGEST = bytes(
    (
        44, 57, 197, 247, 137, 247, 136, 5, 160, 250, 57, 2, 203, 87, 39, 122,
        227, 252, 229, 64, 134, 166, 65, 252, 183, 182, 210, 24, 228, 87, 146, 0,
    )
)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _legacy_mit_grant(notice: bytes) -> bytes:
    marker = b"  MIT License\n"
    start = notice.index(marker)
    lines = notice[start:].splitlines(keepends=True)
    return b"".join(line[2:] if line.startswith(b"  ") else line for line in lines)


def _project_manifests() -> list[Path]:
    return sorted(
        manifest
        for package_root in (ROOT / "packages", ROOT / "packs")
        if package_root.is_dir()
        for manifest in package_root.glob("*/pyproject.toml")
    )


def test_apache_license_and_legacy_notice_are_byte_canonical() -> None:
    license_bytes = (ROOT / "LICENSE").read_bytes()
    notice_bytes = (ROOT / "NOTICE").read_bytes()

    assert _sha256(license_bytes) == APACHE_2_DIGEST
    assert _sha256(_legacy_mit_grant(notice_bytes)) == LEGACY_MIT_GRANT_DIGEST


def test_every_python_artifact_carries_the_same_license_and_notice() -> None:
    license_bytes = (ROOT / "LICENSE").read_bytes()
    notice_bytes = (ROOT / "NOTICE").read_bytes()
    manifests = _project_manifests()
    assert manifests

    for manifest in manifests:
        project = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
        assert project["license"] == "Apache-2.0"
        assert project["license-files"] == ["LICENSE", "NOTICE"]
        assert (manifest.parent / "LICENSE").read_bytes().rstrip(b"\n") == (
            license_bytes.rstrip(b"\n")
        )
        assert (manifest.parent / "NOTICE").read_bytes() == notice_bytes


def test_security_and_ethical_policies_keep_public_private_boundary() -> None:
    security = " ".join((ROOT / "SECURITY.md").read_text(encoding="utf-8").split())
    ethical = " ".join((ROOT / "ETHICAL_USE.md").read_text(encoding="utf-8").split())

    for phrase in (
        "Do not include credentials, personal data, customer names, live target details",
        "fail-closed kill switch and a forward fix",
        "exact release-candidate digest",
        "Do not test a suspected bypass against third-party infrastructure",
    ):
        assert phrase in security

    for phrase in (
        "systems you own or are explicitly authorized to test",
        "Ambiguity is a denial, not permission",
        "destructive actions or high-load testing",
        "automated vulnerability submission or customer-report delivery",
        "does not modify the Apache-2.0 license",
        "Unauthorized access to computer systems is illegal",
    ):
        assert phrase in ethical


def test_third_party_inventory_is_closed_when_present() -> None:
    inventory_path = ROOT / "provenance" / "third_party.json"
    schema_path = ROOT / "provenance" / "third_party.schema.json"
    notices_path = ROOT / "THIRD_PARTY_NOTICES.md"

    present = (inventory_path.exists(), schema_path.exists(), notices_path.exists())
    assert len(set(present)) == 1
    if not all(present):
        return

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert inventory["schema"] == "faultloom.third_party_provenance/v1"
    assert schema["additionalProperties"] is False
    artifact_schema = schema["properties"]["artifacts"]["items"]
    assert artifact_schema["additionalProperties"] is False
    assert set(artifact_schema["required"]) == {
        "path",
        "sha256",
        "source_uri",
        "source_revision",
        "license_spdx",
        "license_file",
    }
    assert set(artifact_schema["properties"]["license_spdx"]["enum"]) == {
        "Apache-2.0",
        "MIT",
    }
