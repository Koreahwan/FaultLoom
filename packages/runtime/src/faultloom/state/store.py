"""Composition root for event, artifact, retrieval, and recovery state."""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cas import ArtifactRef, EncryptedCAS, EngagementKey
from .ledger import EventLedger, EventRecord
from .types import ChainIntegrityError, StorageError, require_identifier


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    engagement_id: str
    chain_head: str
    verified_artifacts: tuple[str, ...]
    quarantined_orphans: tuple[str, ...]
    quarantined_interrupted_writes: tuple[str, ...]
    recovery_id: str | None


class StateStore:
    """Engagement-scoped durable state with encrypted raw observations."""

    def __init__(self, root: Path, engagement_id: str, key: EngagementKey) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        root = Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink():
            raise StorageError("state root must not be a symlink")
        namespace = hashlib.sha256(self.engagement_id.encode("utf-8")).hexdigest()
        engagement_root = root / "engagements" / namespace
        engagement_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.cas = EncryptedCAS(root / "cas", self.engagement_id, key)
        try:
            self.ledger = EventLedger(engagement_root / "state.sqlite3", self.engagement_id)
        except Exception:
            self.cas.close()
            raise
        self._closed = False

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self.ledger.close()
        self.cas.close()
        self._closed = True

    def append_observation(
        self,
        *,
        actor_stream: str,
        event_type: str,
        raw_output: bytes,
        metadata: Mapping[str, Any],
        media_type: str = "application/octet-stream",
    ) -> tuple[EventRecord, ArtifactRef]:
        """Persist full raw bytes before appending their evidence-bearing event."""

        reference = self.cas.put(raw_output, media_type=media_type)
        payload = {
            "artifact_ref": reference.to_dict(),
            "metadata": dict(metadata),
        }
        event = self.ledger.append(
            actor_stream=actor_stream,
            event_type=event_type,
            payload=payload,
            artifacts=(reference,),
        )
        return event, reference

    def index_observation(
        self,
        *,
        doc_id: str,
        event: EventRecord,
        reference: ArtifactRef,
        title: str,
        redacted_text: str,
    ) -> None:
        if event.engagement_id != self.engagement_id:
            raise StorageError("event belongs to another engagement")
        if reference.engagement_id != self.engagement_id:
            raise StorageError("artifact belongs to another engagement")
        self.ledger.add_search_document(
            doc_id=doc_id,
            event_seq=event.seq,
            artifact_sha256=reference.sha256,
            title=title,
            redacted_text=redacted_text,
        )

    def recover(self) -> RecoveryReport:
        """Verify durable state and quarantine uncommitted CAS writes."""

        chain_head = self.ledger.verify_chain()
        interrupted = self.cas.temporary_entries()
        interrupted_labels = tuple(f"{shard}/{name}" for shard, name in interrupted)
        pre_recovery_id: str | None = None
        if interrupted:
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            pre_recovery_id = f"recovery-{stamp}-{secrets.token_hex(4)}"
            for shard, filename in interrupted:
                self.cas.quarantine_temporary(
                    shard, filename, recovery_id=pre_recovery_id
                )
        references = self.ledger.referenced_artifacts()
        verified: list[str] = []
        for reference in references:
            self.cas.get(reference)
            verified.append(reference.sha256)
        referenced = set(verified)
        live = set(self.cas.blob_digests())
        missing = referenced - live
        if missing:
            raise ChainIntegrityError(
                f"ledger references missing encrypted artifacts: {sorted(missing)}"
            )
        orphans = sorted(live - referenced)
        recovery_id: str | None = pre_recovery_id
        if orphans:
            if recovery_id is None:
                stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                recovery_id = f"recovery-{stamp}-{secrets.token_hex(4)}"
            for digest in orphans:
                self.cas.quarantine_orphan(digest, recovery_id=recovery_id)
        return RecoveryReport(
            engagement_id=self.engagement_id,
            chain_head=chain_head,
            verified_artifacts=tuple(sorted(verified)),
            quarantined_orphans=tuple(orphans),
            quarantined_interrupted_writes=interrupted_labels,
            recovery_id=recovery_id,
        )
