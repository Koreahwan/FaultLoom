from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

from faultloom.patch_variant import PatchState
from faultloom_protocol.base import Identifier, ShortStr

DEFAULT_PATCH_VARIANT_MANIFEST: Final = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "patch_variant"
    / "manifest.v1.json"
)


class _FixtureModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DeploymentState(StrEnum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"
    BACKPORTED = "backported"
    AMBIGUOUS = "ambiguous"
    ADVISORY_ONLY = "advisory_only"
    INCOMPLETE_FIX = "incomplete_fix"


class PatchVariantFixtureCase(_FixtureModel):
    case_id: Identifier
    deployment: DeploymentState
    component_present: bool
    path_exposed: bool
    auth_satisfied: bool | None
    config_satisfied: bool | None
    feature_satisfied: bool | None
    patch_state: PatchState
    backport_signal: bool
    expected_conclusion: Literal["reachable", "not_reachable", "ambiguous"]


@dataclass(frozen=True, slots=True)
class PatchVariantFixtureError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


class PatchVariantFixtureManifest(_FixtureModel):
    schema_version: Literal["0.1.0"]
    lab_id: Identifier
    lab_version: Literal["0.1.0"]
    component_name: ShortStr
    cases: tuple[PatchVariantFixtureCase, ...]

    def case(self, case_id: str) -> PatchVariantFixtureCase:
        for fixture_case in self.cases:
            if fixture_case.case_id == case_id:
                return fixture_case
        raise PatchVariantFixtureError(f"unknown patch-variant fixture: {case_id}")


def load_patch_variant_manifest(
    path: Path = DEFAULT_PATCH_VARIANT_MANIFEST,
) -> PatchVariantFixtureManifest:
    return PatchVariantFixtureManifest.model_validate_json(path.read_bytes())
