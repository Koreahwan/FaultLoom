from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from faultloom.state import (
    EngagementKey,
    ProviderCanonicalReceipt,
    ProviderJournalEntry,
    ProviderReceiptMetadata,
    StateStore,
    StorageError,
)
from faultloom.state.canonical import canonical_json


KEY_BYTES = bytes(range(32))


class LyingString(str):
    __hash__ = str.__hash__

    def __eq__(self, _other: Any) -> bool:
        return True

    def __ne__(self, _other: Any) -> bool:
        return False


class LyingInteger(int):
    __hash__ = int.__hash__

    def __eq__(self, _other: Any) -> bool:
        return True

    def __ne__(self, _other: Any) -> bool:
        return False


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def store(root: Path, engagement_id: str) -> StateStore:
    return StateStore(
        root / "state",
        engagement_id,
        EngagementKey(KEY_BYTES),
        anchor_root=root / "anchor",
    )


def database_path(root: Path, engagement_id: str) -> Path:
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    return root / "state" / "engagements" / namespace / "state.sqlite3"


def valid_reservation() -> ProviderJournalEntry:
    metadata = ProviderReceiptMetadata(
        call_id="call/valid",
        attempt=1,
        attempt_id="attempt-valid",
        provider_id="provider.test",
        endpoint_id="endpoint.test",
        profile_digest=digest("profile:valid"),
        requested_alias="model-alias-valid",
        exact_snapshot="model-test-2026-07-14",
        runtime_version="runtime-1.0",
        tokenizer_id="tokenizer.test",
        tokenizer_version="1.0",
        context_window=4096,
        prompt_digest=digest("prompt:valid"),
        compiled_context_digest=digest("context:valid"),
        tool_schema_digest=digest("tools:valid"),
        credential_ref_uri="secret://provider/test-credential",
        credential_ref_purpose="provider.credential",
    )
    return ProviderJournalEntry.from_receipt(
        ProviderCanonicalReceipt.reserved(metadata)
    )


def test_reservation_rejects_receipt_identity_that_contradicts_its_index(
    tmp_path: Path,
) -> None:
    # Given an indexed reservation and canonical receipt declaring another identity.
    engagement_id = "eng.provider-receipt-mismatch"
    receipt_digest = digest("reservation:indexed")
    contradictory_receipt = canonical_json(
        {
            "attempt": 777,
            "attempt_id": "attempt-embedded",
            "binding_digest": digest("binding:embedded"),
            "call_id": "call/embedded",
            "dispatch_reservation_digest": digest("dispatch:embedded"),
            "phase": "finalized",
            "proxy_request_digest": digest("proxy-request:embedded"),
            "receipt_digest": receipt_digest,
            "requested_snapshot": "latest",
            "runtime_version": None,
            "schema_version": "arbitrary.v777",
        }
    )

    with store(tmp_path, engagement_id) as state:
        # When the contradictory receipt crosses the public StateStore boundary.
        with pytest.raises(StorageError, match="canonical provider receipt"):
            state.reserve_provider_receipt(
                ProviderJournalEntry(
                    phase="reserved",
                    receipt_digest=receipt_digest,
                    reservation_receipt_digest=None,
                    call_id="call/indexed",
                    attempt=1,
                    attempt_id="attempt-indexed",
                    binding_digest=digest("binding:indexed"),
                    dispatch_reservation_digest=digest("dispatch:indexed"),
                    proxy_request_digest=digest("proxy-request:indexed"),
                    canonical_receipt_json=contradictory_receipt,
                )
            )

        # Then no mismatched receipt is admitted or anchored.
        assert state.checkpoint().seq == 0


def test_reservation_rejects_raw_secret_before_event_or_projection_durability(
    tmp_path: Path,
) -> None:
    # Given arbitrary receipt JSON containing a unique raw API key marker.
    engagement_id = "eng.provider-receipt-secret"
    marker = "faultloom-secret-marker-attempt4"
    receipt_digest = digest("reservation:secret-bearing")
    secret_bearing_receipt = canonical_json(
        {
            "api_key": marker,
            "kind": "reservation",
            "receipt_digest": receipt_digest,
            "schema_version": "arbitrary.v1",
        }
    )

    with store(tmp_path, engagement_id) as state:
        # When the secret-bearing receipt crosses the public StateStore boundary.
        with pytest.raises(StorageError, match="canonical provider receipt"):
            state.reserve_provider_receipt(
                ProviderJournalEntry(
                    phase="reserved",
                    receipt_digest=receipt_digest,
                    reservation_receipt_digest=None,
                    call_id="call/secret",
                    attempt=1,
                    attempt_id="attempt-secret",
                    binding_digest=digest("binding:secret"),
                    dispatch_reservation_digest=digest("dispatch:secret"),
                    proxy_request_digest=digest("proxy-request:secret"),
                    canonical_receipt_json=secret_bearing_receipt,
                )
            )

        # Then neither authenticated events nor the projection contain the marker.
        assert state.checkpoint().seq == 0
        with sqlite3.connect(database_path(tmp_path, engagement_id)) as connection:
            event_payloads = connection.execute(
                "SELECT payload_json FROM events"
            ).fetchall()
            receipt_payloads = connection.execute(
                "SELECT receipt_json FROM provider_journal_entries"
            ).fetchall()
        assert all(marker not in str(row[0]) for row in event_payloads)
        assert all(marker not in str(row[0]) for row in receipt_payloads)


def test_state_boundary_revalidates_entry_before_serializing(tmp_path: Path) -> None:
    entry = valid_reservation()
    object.__setattr__(entry, "call_id", "call/forged")

    with store(tmp_path, "eng.provider-receipt-forged") as state:
        with pytest.raises(StorageError, match="differs from indexed identity"):
            state.reserve_provider_receipt(entry)
        assert state.checkpoint().seq == 0


def test_entry_rejects_lying_string_subclasses_before_identity_comparison() -> None:
    # Given valid receipt JSON paired with forged string-subclass indexes.
    entry = valid_reservation()

    # When overloaded equality claims every forged index matches the receipt.
    with pytest.raises(StorageError, match="canonical provider receipt"):
        ProviderJournalEntry(
            phase=entry.phase,
            receipt_digest=LyingString(digest("receipt:forged")),
            reservation_receipt_digest=None,
            call_id=LyingString("call/forged"),
            attempt=LyingInteger(777),
            attempt_id=LyingString("attempt-forged"),
            binding_digest=LyingString(digest("binding:forged")),
            dispatch_reservation_digest=LyingString(digest("dispatch:forged")),
            proxy_request_digest=LyingString(digest("request:forged")),
            canonical_receipt_json=entry.canonical_receipt_json,
        )

    # Then the boundary rejects the non-exact primitives before comparing them.


def test_parser_rejects_lie_capable_json_string_subclass() -> None:
    # Given canonical JSON with a forged embedded receipt digest.
    entry = valid_reservation()
    forged_json = entry.canonical_receipt_json.replace(
        f'"receipt_digest":"{entry.receipt_digest}"',
        f'"receipt_digest":"{digest("receipt:forged-json")}"',
        1,
    )

    # When the JSON string subclass lies during the canonical equality checks.
    with pytest.raises(StorageError, match="canonical provider receipt"):
        ProviderCanonicalReceipt.parse(LyingString(forged_json))

    # Then parsing rejects the non-exact string before decoding or comparing it.


def test_parser_translates_unpaired_surrogate_to_storage_error() -> None:
    # Given exact built-in JSON containing an unpaired surrogate in allowed text.
    entry = valid_reservation()
    surrogate_json = entry.canonical_receipt_json.replace(
        "model-alias-valid", "\ud800"
    )

    # When the parser reaches canonical digest encoding.
    with pytest.raises(StorageError, match="canonical provider receipt"):
        ProviderCanonicalReceipt.parse(surrogate_json)

    # Then the public boundary returns its typed error instead of an encoding leak.
