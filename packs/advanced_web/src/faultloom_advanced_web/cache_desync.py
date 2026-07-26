"""Normalize read-only cache evidence without promoting it to an effect by itself."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol

from faultloom_protocol import SCHEMA_VERSION
from faultloom_sdk import NormalizedObservation

_NORMALIZER_ID = "advanced_web.cache_desync.normalizer"
_ADAPTER_ID = "adapter.advanced_web.loopback"
CaseId = Literal["positive", "negative"]


@dataclass(frozen=True)
class ReadOnlyResponse(Protocol):
    url: str
    body: bytes
    headers: tuple[tuple[str, str], ...]

    def header(self, name: str) -> str: ...


class CacheDesyncObservationSource(Protocol):
    def read(
        self,
        case_id: CaseId,
        evidence: Literal["stale", "fresh", "final-effect"],
    ) -> ReadOnlyResponse: ...


@dataclass(frozen=True)
class CacheDesyncEvidence:
    normalized_observation: NormalizedObservation
    case_id: CaseId
    stale_epoch: int
    fresh_epoch: int
    expected_epoch: int
    stale_age: int
    stale_cache_hit: bool
    epoch_mismatch: bool
    classification: Literal["diagnostic_candidate", "matched_negative_control"]


@dataclass(frozen=True)
class CacheDesyncVerdict:
    classification: Literal["candidate_only", "negative_control"]


@dataclass(frozen=True)
class CacheDesyncRun:
    evidence: CacheDesyncEvidence
    verdict: CacheDesyncVerdict


def observe_cache_desync(
    source: CacheDesyncObservationSource,
    case_id: CaseId,
    *,
    read_final_effect: bool = True,
) -> CacheDesyncRun:
    """Read the deterministic pair and its inert canary using loopback GET only."""

    stale = source.read(case_id, "stale")
    fresh = source.read(case_id, "fresh")
    evidence = normalize_cache_desync(case_id, stale, fresh)
    final = source.read(case_id, "final-effect") if read_final_effect else None
    return CacheDesyncRun(
        evidence=evidence,
        verdict=classify_final_effect_candidate(evidence, final),
    )


def normalize_cache_desync(
    case_id: CaseId, stale: ReadOnlyResponse, fresh: ReadOnlyResponse
) -> CacheDesyncEvidence:
    """Create candidate-only evidence from stale/fresh cache observations."""

    stale_epoch = int(stale.header("X-Fixture-Epoch"))
    fresh_epoch = int(fresh.header("X-Fixture-Epoch"))
    stale_age = int(stale.header("Age"))
    stale_cache_hit = stale.header("X-Cache") == "HIT"
    epoch_mismatch = stale_epoch < fresh_epoch
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    classification = (
        "diagnostic_candidate"
        if stale_cache_hit and epoch_mismatch
        else "matched_negative_control"
    )
    return CacheDesyncEvidence(
        normalized_observation=NormalizedObservation(
            schema_version=SCHEMA_VERSION,
            adapter_id=_ADAPTER_ID,
            normalizer_id=_NORMALIZER_ID,
            observation_id=f"observation.cache-desync.{case_id}",
            source_digest=_digest(stale.body + b"\0" + fresh.body),
        ),
        case_id=case_id,
        stale_epoch=stale_epoch,
        fresh_epoch=fresh_epoch,
        expected_epoch=fresh_epoch,
        stale_age=stale_age,
        stale_cache_hit=stale_cache_hit,
        epoch_mismatch=epoch_mismatch,
        classification=classification,
    )


def classify_final_effect_candidate(
    evidence: CacheDesyncEvidence, final: ReadOnlyResponse | None = None
) -> CacheDesyncVerdict:
    """Keep every protocol response candidate-only until an authenticated adapter exists."""

    _ = final
    if evidence.classification != "diagnostic_candidate":
        return CacheDesyncVerdict("negative_control")
    return CacheDesyncVerdict("candidate_only")


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
