from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from faultloom.state import (
    EngagementKey,
    ProviderCanonicalReceipt,
    ProviderJournalEntry,
    ProviderReceiptMetadata,
    StateStore,
)


KEY_BYTES = bytes(range(32))


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def receipt_metadata(
    *,
    label: str,
    call_id: str,
    attempt: int,
    attempt_id: str,
) -> ProviderReceiptMetadata:
    return ProviderReceiptMetadata(
        call_id=call_id,
        attempt=attempt,
        attempt_id=attempt_id,
        provider_id="provider.test",
        endpoint_id="endpoint.test",
        profile_digest=digest(f"profile:{label}"),
        requested_alias=f"model-alias-{label}",
        exact_snapshot="model-test-2026-07-14",
        runtime_version="runtime-1.0",
        tokenizer_id="tokenizer.test",
        tokenizer_version="1.0",
        context_window=4096,
        prompt_digest=digest(f"prompt:{label}"),
        compiled_context_digest=digest(f"context:{label}"),
        tool_schema_digest=digest(f"tools:{label}"),
        credential_ref_uri="secret://provider/test-credential",
        credential_ref_purpose="provider.credential",
    )


def reservation(
    *,
    label: str = "one",
    call_id: str = "call/one",
    attempt: int = 1,
    attempt_id: str = "attempt-one",
) -> ProviderJournalEntry:
    receipt = ProviderCanonicalReceipt.reserved(
        receipt_metadata(
            label=label,
            call_id=call_id,
            attempt=attempt,
            attempt_id=attempt_id,
        )
    )
    return ProviderJournalEntry.from_receipt(receipt)


def terminal(
    reserved: ProviderJournalEntry, *, label: str = "success"
) -> ProviderJournalEntry:
    receipt = ProviderCanonicalReceipt.parse(reserved.canonical_receipt_json)
    return ProviderJournalEntry.from_receipt(
        receipt.finalized(digest(f"result:{label}"))
    )


def store(root: Path, engagement_id: str = "eng.provider") -> StateStore:
    return StateStore(
        root / "state",
        engagement_id,
        EngagementKey(KEY_BYTES),
        anchor_root=root / "anchor",
    )


def database_path(root: Path, engagement_id: str = "eng.provider") -> Path:
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    return root / "state" / "engagements" / namespace / "state.sqlite3"


def downgrade_empty_provider_projection_to_v2(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM provider_journal_entries"
        ).fetchone()[0] == 0
        connection.execute("DROP TABLE provider_journal_entries")
        connection.execute("PRAGMA user_version=2")
        connection.commit()
