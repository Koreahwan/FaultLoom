"""Future advanced-Web descriptors that remain isolated from the v0.1 Web pack."""

from .cache_desync import (
    CacheDesyncEvidence,
    CacheDesyncRun,
    CacheDesyncVerdict,
    classify_final_effect_candidate,
    observe_cache_desync,
)
from .manifest import advanced_web_manifest
from .raw_message import (
    RawMessageEvidence,
    RawMessageRun,
    RawMessageVerdict,
    observe_raw_message,
)
from .race import (
    RaceTransition,
    RaceWindowEvidence,
    RaceWindowRun,
    RaceWindowVerdict,
    observe_race_window,
    verify_race_final_effect,
)

__all__ = [
    "CacheDesyncEvidence",
    "CacheDesyncRun",
    "CacheDesyncVerdict",
    "RawMessageEvidence",
    "RawMessageRun",
    "RawMessageVerdict",
    "RaceTransition",
    "RaceWindowEvidence",
    "RaceWindowRun",
    "RaceWindowVerdict",
    "advanced_web_manifest",
    "classify_final_effect_candidate",
    "observe_cache_desync",
    "observe_raw_message",
    "observe_race_window",
    "verify_race_final_effect",
]
