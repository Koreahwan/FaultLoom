from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol.base import Identifier

API_ASYNC_LAB_SCHEMA_VERSION: Final = "0.1.0"
DEFAULT_FIXTURE_ROOT: Final = Path(__file__).resolve().parents[1] / "fixtures" / "api_async"
SemVer = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


class _FixtureModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AsyncSurfaceKind(StrEnum):
    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    WEBHOOK = "webhook"
    JOB = "job"
    FILE = "file"


class FixturePolarity(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class AsyncFixtureError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class AsyncFixtureVariant(_FixtureModel):
    variant_id: Identifier
    polarity: FixturePolarity
    identity_context_id: Identifier
    tenant_id: Identifier
    expected_authorized: bool
    expected_effect: Identifier

    @model_validator(mode="after")
    def _authorization_matches_polarity(self) -> Self:
        expected = self.polarity is FixturePolarity.POSITIVE
        if self.expected_authorized != expected:
            raise AsyncFixtureError("fixture authorization differs from its polarity")
        return self


class AsyncSurfaceLabManifest(_FixtureModel):
    schema_version: Literal["0.1.0"]
    lab_id: Identifier
    lab_version: SemVer
    fixture_id: Identifier
    fixture_version: SemVer
    namespace: Identifier
    surface_kind: AsyncSurfaceKind
    target_id: Identifier
    bind_host: Literal["127.0.0.1"]
    variants: tuple[AsyncFixtureVariant, ...]

    @model_validator(mode="after")
    def _has_control_pair(self) -> Self:
        if len(self.variants) != 2:
            raise AsyncFixtureError("API/async fixture requires exactly two variants")
        polarities = frozenset(item.polarity for item in self.variants)
        if polarities != frozenset({FixturePolarity.POSITIVE, FixturePolarity.NEGATIVE}):
            raise AsyncFixtureError("API/async fixture requires positive and negative variants")
        if len({item.variant_id for item in self.variants}) != 2:
            raise AsyncFixtureError("API/async fixture variant IDs must be unique")
        return self


def load_api_async_manifest(surface: AsyncSurfaceKind) -> AsyncSurfaceLabManifest:
    path = DEFAULT_FIXTURE_ROOT / surface.value / "manifest.v1.json"
    return AsyncSurfaceLabManifest.model_validate_json(path.read_bytes())


def load_all_api_async_manifests() -> tuple[AsyncSurfaceLabManifest, ...]:
    return tuple(load_api_async_manifest(surface) for surface in AsyncSurfaceKind)
