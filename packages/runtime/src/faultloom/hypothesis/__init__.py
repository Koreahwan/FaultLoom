from .models import (
    HypothesisCursor,
    HypothesisCursorError,
    HypothesisGraphState,
    HypothesisPage,
    HypothesisSeed,
    NegativeResultSeed,
    ResearchContextRecords,
    hypothesis_id_for,
    negative_result_id_for,
)


def __getattr__(name: str) -> object:
    """Keep durable journal imports out of pure hypothesis-model consumers."""

    if name == "HypothesisConflictError":
        from .journal import HypothesisConflictError

        globals()[name] = HypothesisConflictError
        return HypothesisConflictError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "HypothesisConflictError",
    "HypothesisCursor",
    "HypothesisCursorError",
    "HypothesisGraphState",
    "HypothesisPage",
    "HypothesisSeed",
    "NegativeResultSeed",
    "ResearchContextRecords",
    "hypothesis_id_for",
    "negative_result_id_for",
]
