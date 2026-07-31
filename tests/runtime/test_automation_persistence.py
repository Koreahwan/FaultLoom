from __future__ import annotations

from faultloom.automation.persistence import (
    AUTOMATION_TURN_EVENT_TYPE,
    load_automation_turn,
    persist_automation_turn,
)
from tests.runtime.resume_support import open_store
from tests.runtime.test_authorized_automation import (
    _coordinator,
    _request,
    _safe_action,
    _turn,
)


def test_validated_turn_is_one_encrypted_idempotent_event(tmp_path) -> None:
    result = _coordinator().run(
        request=_request(),
        raw_model_turn=_turn(action=_safe_action()),
    )
    with open_store(tmp_path) as store:
        first = persist_automation_turn(store, result)
        second = persist_automation_turn(store, result)

        assert second == first
        assert first.event_type == AUTOMATION_TURN_EVENT_TYPE
        assert load_automation_turn(store, first).result == result
        assert store.ledger is not None
        assert tuple(
            event
            for event in store.ledger.events(limit=100)
            if event.event_type == AUTOMATION_TURN_EVENT_TYPE
        ) == (first,)
        assert "summary" not in str(first.payload)
        assert "invoice normalizer" not in str(first.payload)
