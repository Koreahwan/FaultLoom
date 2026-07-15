from __future__ import annotations

from typing import NamedTuple

from faultloom.state import EncryptedCAS, EventLedger, StateStore

from .contracts import ProviderOutputIntegrityError

STATE_APPEND = StateStore.append_observation
STATE_CHECKPOINT = StateStore.checkpoint
LEDGER_EVENTS = EventLedger.events
LEDGER_REFERENCES = EventLedger.referenced_artifacts
LEDGER_VERIFY = EventLedger.verify_chain
CAS_READ_PAGE = EncryptedCAS.read_page


class StoreAdmission(NamedTuple):
    state: StateStore
    engagement_id: str
    max_artifact_bytes: int


def trusted_store_admission(value: object) -> StoreAdmission:
    if (
        type(value) is not StoreAdmission
        or type(value.state) is not StateStore
        or type(value.engagement_id) is not str
        or not value.engagement_id
        or type(value.max_artifact_bytes) is not int
        or not 1 <= value.max_artifact_bytes <= 2**31
    ):
        raise ProviderOutputIntegrityError(
            "provider output store admission changed"
        )
    return value


def method_is_original(owner: type[object], name: str, expected: object) -> bool:
    namespace = type.__getattribute__(owner, "__dict__")
    return namespace.get(name) is expected


def instance_values(value: object) -> dict[str, object]:
    namespace = object.__getattribute__(value, "__dict__")
    if type(namespace) is not dict or any(type(key) is not str for key in namespace):
        raise ProviderOutputIntegrityError(
            "provider output capability namespace is invalid"
        )
    return namespace
