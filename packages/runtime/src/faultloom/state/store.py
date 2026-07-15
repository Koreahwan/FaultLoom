"""Composition root for anchored event, artifact, retrieval, and recovery state."""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .anchor import AnchorCheckpoint, AuthenticatedAnchor, EngagementLock, ZERO_HASH
from .canonical import canonical_json
from .cas import ArtifactRef, EncryptedCAS, EngagementKey
from .filesystem import DirectoryBinding, open_private_directory
from .ledger import EventLedger, EventRecord
from .provider_journal import ProviderJournalEntry, ProviderJournalRecord
from .types import ChainIntegrityError, CrossEngagementError, StorageError, require_identifier


METADATA_MEDIA_TYPE = "application/vnd.faultloom.observation-metadata+json"


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    engagement_id: str
    chain_head: str
    verified_artifacts: tuple[str, ...]
    quarantined_orphans: tuple[str, ...]
    quarantined_interrupted_writes: tuple[str, ...]
    reconciled_publications: tuple[str, ...]
    recovery_id: str | None
    anchor: AnchorCheckpoint


def _absolute_root(path: Path, *, field: str) -> Path:
    value = Path(path)
    if not value.is_absolute() or any(part in {"", ".", ".."} for part in value.parts[1:]):
        raise StorageError(f"{field} must be an absolute canonical path")
    return value


def _require_separate_roots(state_root: Path, anchor_root: Path) -> None:
    common = Path(os.path.commonpath((state_root, anchor_root)))
    if common in {state_root, anchor_root}:
        raise StorageError("anchor_root must be outside the mutable state root")


def _open_optional_directory(parent_fd: int, name: str) -> int | None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return open_private_directory(parent_fd, name, create=False)


def _engagement_state_exists(root_fd: int, namespace: str) -> bool:
    for container_name in ("engagements", "cas"):
        container_fd = _open_optional_directory(root_fd, container_name)
        if container_fd is None:
            continue
        try:
            namespace_fd = _open_optional_directory(container_fd, namespace)
            if namespace_fd is None:
                continue
            try:
                if os.listdir(namespace_fd):
                    return True
            finally:
                os.close(namespace_fd)
        finally:
            os.close(container_fd)
    return False


class StateStore:
    """Engagement-scoped durable state with encrypted raw observations.

    ``anchor_root`` must live outside ``root`` and must be backed up or retained
    independently. A caller that needs rollback resistance across anchor-store
    restoration must also retain and pass ``minimum_anchor`` from fresher
    trusted state. Authentication alone cannot prove that an old valid anchor
    is fresh.
    """

    def __init__(
        self,
        root: Path,
        engagement_id: str,
        key: EngagementKey,
        *,
        anchor_root: Path,
        minimum_anchor: AnchorCheckpoint | None = None,
    ) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        self.root = _absolute_root(Path(root), field="root")
        self.anchor_root = _absolute_root(Path(anchor_root), field="anchor_root")
        _require_separate_roots(self.root, self.anchor_root)
        if minimum_anchor is not None and minimum_anchor.engagement_id != self.engagement_id:
            raise CrossEngagementError("minimum anchor belongs to another engagement")
        self._minimum_anchor = minimum_anchor
        self.anchor: AuthenticatedAnchor | None = None
        self.cas: EncryptedCAS | None = None
        self.ledger: EventLedger | None = None
        self._closed = False
        self._state_binding = DirectoryBinding(
            self.root, create=True, context="configured state root"
        )
        try:
            self._anchor_binding = DirectoryBinding(
                self.anchor_root, create=True, context="external anchor root"
            )
        except Exception:
            self._state_binding.close()
            self._closed = True
            raise
        try:
            self._lock = EngagementLock(
                self.anchor_root,
                self.engagement_id,
                path_validator=self._revalidate_roots,
            )
        except Exception:
            self._anchor_binding.close()
            self._state_binding.close()
            self._closed = True
            raise
        namespace = hashlib.sha256(self.engagement_id.encode("utf-8")).hexdigest()
        try:
            with self._lock:
                self._revalidate_roots()
                state_root_fd = self._state_binding.descriptor
                existing_state = _engagement_state_exists(state_root_fd, namespace)
                self.anchor = AuthenticatedAnchor(
                    self.anchor_root,
                    self.engagement_id,
                    key,
                    path_validator=self._revalidate_roots,
                )
                checkpoint = self.anchor.load_optional()
                if checkpoint is None:
                    if existing_state:
                        raise ChainIntegrityError(
                            "authenticated anchor is missing for existing engagement state"
                        )
                    checkpoint = AnchorCheckpoint(
                        engagement_id=self.engagement_id,
                        seq=0,
                        head=ZERO_HASH,
                    )
                    self.anchor.write(checkpoint)
                self._validate_minimum(checkpoint, ledger=None)
                engagements_fd = open_private_directory(
                    state_root_fd, "engagements", create=True
                )
                try:
                    engagement_fd = open_private_directory(
                        engagements_fd, namespace, create=True
                    )
                    os.close(engagement_fd)
                finally:
                    os.close(engagements_fd)
                cas_fd = open_private_directory(state_root_fd, "cas", create=True)
                os.close(cas_fd)
                self.cas = EncryptedCAS(
                    self.root / "cas",
                    self.engagement_id,
                    key,
                    path_validator=self._revalidate_roots,
                )
                self.ledger = EventLedger(
                    self.root / "engagements" / namespace / "state.sqlite3",
                    self.engagement_id,
                    key,
                    transaction_lock=self._lock,
                    commit_callback=self._synchronize_anchor,
                    path_validator=self._revalidate_roots,
                    migration_anchor=checkpoint,
                    migration_minimum_anchor=self._minimum_anchor,
                )
                self._synchronize_anchor()
        except Exception:
            if self.ledger is not None:
                try:
                    self.ledger.close()
                except Exception:
                    pass
            if self.cas is not None:
                try:
                    self.cas.close()
                except Exception:
                    pass
            if self.anchor is not None:
                try:
                    self.anchor.close()
                except Exception:
                    pass
            try:
                self._lock.close()
            except Exception:
                pass
            self._anchor_binding.close()
            self._state_binding.close()
            self._closed = True
            raise

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _components(self) -> tuple[EventLedger, EncryptedCAS, AuthenticatedAnchor]:
        if self._closed or self.ledger is None or self.cas is None or self.anchor is None:
            raise StorageError("state store is closed")
        return self.ledger, self.cas, self.anchor

    @property
    def minimum_anchor(self) -> AnchorCheckpoint | None:
        """The caller-retained freshness floor bound at construction."""

        return self._minimum_anchor

    def _revalidate_roots(self) -> None:
        self._state_binding.revalidate()
        self._anchor_binding.revalidate()

    def close(self) -> None:
        if self._closed:
            return
        ledger, cas, anchor = self._components()
        failure: Exception | None = None

        def remember(exc: Exception) -> None:
            nonlocal failure
            if failure is None:
                failure = exc

        def finalize_verified_snapshot(snapshot: tuple[int, str]) -> None:
            self._synchronize_anchor_from_checkpoint(
                ledger, anchor, snapshot
            )
            cas.close()
            anchor.close()

        try:
            with self._lock:
                # Preserve the ordinary checkpoint boundary, then independently
                # authenticate the close snapshot under its own writer lock.
                self._synchronize_anchor()
                ledger.close_verified(finalize_verified_snapshot)
        except Exception as exc:
            remember(exc)
        for component in (ledger, cas, anchor, self._lock):
            try:
                component.close()
            except Exception as exc:
                remember(exc)
        try:
            self._revalidate_roots()
        except Exception as exc:
            remember(exc)
        finally:
            self._anchor_binding.close()
            self._state_binding.close()
            self._closed = True
        if failure is not None:
            raise failure

    def _validate_minimum(
        self, checkpoint: AnchorCheckpoint, *, ledger: EventLedger | None
    ) -> None:
        floor = self._minimum_anchor
        if floor is None:
            return
        if checkpoint.seq < floor.seq:
            raise ChainIntegrityError("authenticated anchor is older than the trusted floor")
        if checkpoint.seq == floor.seq:
            if checkpoint.head != floor.head:
                raise ChainIntegrityError("authenticated anchor diverges from the trusted floor")
            return
        if floor.seq == 0:
            if floor.head != ZERO_HASH:
                raise ChainIntegrityError("trusted empty anchor has an invalid head")
            return
        if ledger is None:
            return
        if ledger._event_hash_at_in_transaction(floor.seq) != floor.head:
            raise ChainIntegrityError("event chain does not contain the trusted anchor floor")

    def _synchronize_anchor_from_checkpoint(
        self,
        ledger: EventLedger,
        anchor_store: AuthenticatedAnchor,
        snapshot: tuple[int, str],
    ) -> AnchorCheckpoint:
        seq, head = snapshot
        checkpoint = anchor_store.load_optional()
        if checkpoint is None:
            raise ChainIntegrityError("authenticated anchor disappeared")
        if checkpoint.seq > seq:
            raise ChainIntegrityError("event ledger is behind its authenticated anchor")
        if checkpoint.seq == seq:
            if checkpoint.head != head:
                raise ChainIntegrityError(
                    "event ledger head differs from its authenticated anchor"
                )
        else:
            if checkpoint.seq == 0:
                if checkpoint.head != ZERO_HASH:
                    raise ChainIntegrityError("empty authenticated anchor is invalid")
            elif ledger._event_hash_at_in_transaction(checkpoint.seq) != checkpoint.head:
                raise ChainIntegrityError(
                    "event ledger diverged before its authenticated anchor"
                )
            candidate = AnchorCheckpoint(
                engagement_id=self.engagement_id,
                seq=seq,
                head=head,
            )
            self._validate_minimum(candidate, ledger=ledger)
            anchor_store.write(candidate)
            persisted = anchor_store.load_optional()
            if persisted != candidate:
                raise ChainIntegrityError(
                    "authenticated anchor update was not durable"
                )
            checkpoint = candidate
        self._validate_minimum(checkpoint, ledger=ledger)
        return checkpoint

    def _synchronize_anchor(self) -> AnchorCheckpoint:
        ledger, _, anchor_store = self._components()
        with ledger.verified_checkpoint() as snapshot:
            return self._synchronize_anchor_from_checkpoint(
                ledger, anchor_store, snapshot
            )

    def checkpoint(self) -> AnchorCheckpoint:
        with self._lock:
            return self._synchronize_anchor()

    def _require_exact_provider_store(self) -> None:
        if type(self) is not StateStore:
            raise StorageError("provider journal requires the exact StateStore")

    def reserve_provider_receipt(
        self, entry: ProviderJournalEntry
    ) -> ProviderJournalRecord:
        """Atomically reserve a provider attempt and durably anchor the receipt."""

        self._require_exact_provider_store()
        with self._lock:
            ledger, _, _ = self._components()
            return ledger.reserve_provider_receipt(
                entry,
                state_store=self,
                minimum_anchor=self._minimum_anchor,
            )

    def finalize_provider_receipt(
        self,
        reservation_receipt_digest: str,
        entry: ProviderJournalEntry,
    ) -> ProviderJournalRecord:
        """CAS a terminal provider receipt onto its exact reservation."""

        self._require_exact_provider_store()
        with self._lock:
            ledger, _, _ = self._components()
            return ledger.finalize_provider_receipt(
                reservation_receipt_digest,
                entry,
                state_store=self,
                minimum_anchor=self._minimum_anchor,
            )

    def provider_receipt_by_digest(
        self, receipt_digest: str
    ) -> ProviderJournalRecord | None:
        self._require_exact_provider_store()
        with self._lock:
            ledger, _, _ = self._components()
            return ledger.provider_receipt_by_digest(
                receipt_digest,
                state_store=self,
                minimum_anchor=self._minimum_anchor,
            )

    def provider_receipt_by_attempt(
        self, call_id: str, attempt: int
    ) -> ProviderJournalRecord | None:
        self._require_exact_provider_store()
        with self._lock:
            ledger, _, _ = self._components()
            return ledger.provider_receipt_by_attempt(
                call_id,
                attempt,
                state_store=self,
                minimum_anchor=self._minimum_anchor,
            )

    def provider_receipt_by_attempt_id(
        self, attempt_id: str
    ) -> ProviderJournalRecord | None:
        self._require_exact_provider_store()
        with self._lock:
            ledger, _, _ = self._components()
            return ledger.provider_receipt_by_attempt_id(
                attempt_id,
                state_store=self,
                minimum_anchor=self._minimum_anchor,
            )

    def append_observation(
        self,
        *,
        actor_stream: str,
        event_type: str,
        raw_output: bytes,
        metadata: Mapping[str, Any],
        media_type: str = "application/octet-stream",
    ) -> tuple[EventRecord, ArtifactRef]:
        """Encrypt raw output and typed metadata before anchoring their references."""

        if not isinstance(metadata, Mapping):
            raise StorageError("observation metadata must be an object")
        metadata_bytes = canonical_json(
            {"schema_version": 1, "values": dict(metadata)}
        ).encode("utf-8")
        with self._lock:
            self._synchronize_anchor()
            ledger, cas, _ = self._components()
            reference = cas.put(raw_output, media_type=media_type)
            metadata_reference = cas.put(
                metadata_bytes, media_type=METADATA_MEDIA_TYPE
            )
            payload = {
                "artifact_ref": reference.to_dict(),
                "metadata_ref": metadata_reference.to_dict(),
                "metadata_schema_version": 1,
            }
            event = ledger.append(
                actor_stream=actor_stream,
                event_type=event_type,
                payload=payload,
                artifacts=(reference, metadata_reference),
            )
            self._synchronize_anchor()
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
        with self._lock:
            self._synchronize_anchor()
            ledger, _, _ = self._components()
            ledger.add_search_document(
                doc_id=doc_id,
                event_seq=event.seq,
                artifact_sha256=reference.sha256,
                title=title,
                redacted_text=redacted_text,
            )
            self._synchronize_anchor()

    def recover(self) -> RecoveryReport:
        """Verify anchored state and atomically quarantine uncommitted CAS writes."""

        with self._lock:
            ledger, cas, anchor_store = self._components()
            with ledger.verified_checkpoint() as snapshot:
                checkpoint = self._synchronize_anchor_from_checkpoint(
                    ledger, anchor_store, snapshot
                )
                interrupted = cas.temporary_entries()
                interrupted_labels: list[str] = []
                reconciled: list[str] = []
                pre_recovery_id: str | None = None
                if interrupted:
                    stamp = dt.datetime.now(dt.timezone.utc).strftime(
                        "%Y%m%dT%H%M%S%fZ"
                    )
                    pre_recovery_id = f"recovery-{stamp}-{secrets.token_hex(4)}"
                    for shard, filename in interrupted:
                        label = f"{shard}/{filename}"
                        result = cas.quarantine_temporary(
                            shard, filename, recovery_id=pre_recovery_id
                        )
                        if result == "published":
                            reconciled.append(label)
                        else:
                            interrupted_labels.append(label)
                references = ledger._referenced_artifacts_in_transaction()
                verified: list[str] = []
                for reference in references:
                    cas.get(reference)
                    verified.append(reference.sha256)
                referenced = set(verified)
                live = set(cas.blob_digests())
                missing = referenced - live
                if missing:
                    raise ChainIntegrityError(
                        "ledger references missing encrypted artifacts: "
                        f"{sorted(missing)}"
                    )
                orphans = sorted(live - referenced)
                recovery_id: str | None = (
                    pre_recovery_id if interrupted_labels else None
                )
                if orphans:
                    if recovery_id is None:
                        stamp = dt.datetime.now(dt.timezone.utc).strftime(
                            "%Y%m%dT%H%M%S%fZ"
                        )
                        recovery_id = f"recovery-{stamp}-{secrets.token_hex(4)}"
                    for digest in orphans:
                        cas.quarantine_orphan(digest, recovery_id=recovery_id)
                return RecoveryReport(
                    engagement_id=self.engagement_id,
                    chain_head=checkpoint.head,
                    verified_artifacts=tuple(sorted(verified)),
                    quarantined_orphans=tuple(orphans),
                    quarantined_interrupted_writes=tuple(interrupted_labels),
                    reconciled_publications=tuple(reconciled),
                    recovery_id=recovery_id,
                    anchor=checkpoint,
                )
