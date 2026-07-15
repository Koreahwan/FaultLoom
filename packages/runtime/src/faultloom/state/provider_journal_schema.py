"""Exact SQLite schema for the append-only provider receipt projection."""

PROVIDER_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS provider_journal_entries (
        receipt_digest TEXT PRIMARY KEY,
        phase TEXT NOT NULL CHECK (phase IN ('reserved', 'finalized')),
        reservation_receipt_digest TEXT
            REFERENCES provider_journal_entries(receipt_digest),
        call_id TEXT NOT NULL,
        attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 9223372036854775807),
        attempt_id TEXT NOT NULL,
        binding_digest TEXT NOT NULL,
        dispatch_reservation_digest TEXT NOT NULL,
        proxy_request_digest TEXT NOT NULL,
        receipt_json TEXT NOT NULL,
        anchor_event_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq),
        CHECK (
            (phase = 'reserved' AND reservation_receipt_digest IS NULL) OR
            (phase = 'finalized' AND reservation_receipt_digest IS NOT NULL
                                 AND reservation_receipt_digest <> receipt_digest)
        )
    ) WITHOUT ROWID
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_call_attempt_uq
    ON provider_journal_entries(call_id, attempt) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_attempt_id_uq
    ON provider_journal_entries(attempt_id) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_dispatch_uq
    ON provider_journal_entries(dispatch_reservation_digest) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_request_uq
    ON provider_journal_entries(proxy_request_digest) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_finalization_once_uq
    ON provider_journal_entries(reservation_receipt_digest) WHERE phase = 'finalized'
    """,
    """
    CREATE TRIGGER IF NOT EXISTS provider_journal_entries_no_update
    BEFORE UPDATE ON provider_journal_entries
    BEGIN SELECT RAISE(ABORT, 'append-only provider journal'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS provider_journal_entries_no_delete
    BEFORE DELETE ON provider_journal_entries
    BEGIN SELECT RAISE(ABORT, 'append-only provider journal'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS provider_journal_finalization_binding
    BEFORE INSERT ON provider_journal_entries
    WHEN NEW.phase = 'finalized'
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM provider_journal_entries AS reserved
            WHERE reserved.phase = 'reserved'
              AND reserved.receipt_digest = NEW.reservation_receipt_digest
              AND reserved.call_id = NEW.call_id
              AND reserved.attempt = NEW.attempt
              AND reserved.attempt_id = NEW.attempt_id
              AND reserved.binding_digest = NEW.binding_digest
              AND reserved.dispatch_reservation_digest = NEW.dispatch_reservation_digest
              AND reserved.proxy_request_digest = NEW.proxy_request_digest
        ) THEN RAISE(ABORT, 'provider finalization binding mismatch') END;
    END
    """,
)

PROVIDER_SCHEMA = ";\n".join(
    statement.strip() for statement in PROVIDER_SCHEMA_STATEMENTS
) + ";\n"
