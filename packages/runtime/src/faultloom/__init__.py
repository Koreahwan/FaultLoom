"""FaultLoom public runtime."""

__version__ = "0.1.0"

_STATE_EXPORTS = (
    "AnchorCheckpoint",
    "ArtifactRef",
    "ChainIntegrityError",
    "CrossEngagementError",
    "EncryptedCAS",
    "EngagementKey",
    "EventLedger",
    "EventRecord",
    "RecoveryReport",
    "RetrievalPage",
    "StateStore",
    "StorageError",
)

__all__ = [*_STATE_EXPORTS, "__version__"]


def __getattr__(name: str) -> object:
    if name not in _STATE_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from . import state

    value = getattr(state, name)
    globals()[name] = value
    return value
