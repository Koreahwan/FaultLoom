from __future__ import annotations

from typing import Protocol

from faultloom.state import ArtifactRef, EncryptedCAS, EventLedger, RetrievalPage

from ._store_support import CAS_READ_PAGE, LEDGER_REFERENCES
from .contracts import ProviderOutputIntegrityError

class ArtifactStoreBinding(Protocol):
    def ledger(self) -> EventLedger: ...

    def cas(self) -> EncryptedCAS: ...


def artifact_references(
    binding: ArtifactStoreBinding,
) -> tuple[ArtifactRef, ...]:
    return LEDGER_REFERENCES(binding.ledger())


def read_artifact_page(
    binding: ArtifactStoreBinding,
    reference: ArtifactRef,
    *,
    cursor: str | None,
    max_bytes: int,
) -> RetrievalPage:
    try:
        page = CAS_READ_PAGE(
            binding.cas(),
            reference,
            cursor=cursor,
            max_bytes=max_bytes,
        )
    except Exception as exc:
        raise ProviderOutputIntegrityError(
            "provider output storage read failed"
        ) from exc
    if type(page) is not RetrievalPage:
        raise ProviderOutputIntegrityError(
            "provider output storage returned an invalid page"
        )
    return page


def verify_artifact_reference(
    binding: ArtifactStoreBinding,
    reference: ArtifactRef,
) -> None:
    page = read_artifact_page(binding, reference, cursor=None, max_bytes=1)
    expected_page_bytes = min(reference.byte_length, 1)
    if (
        page.offset != 0
        or page.total_bytes != reference.byte_length
        or len(page.data) != expected_page_bytes
        or (
            reference.byte_length <= 1
            and page.next_cursor is not None
        )
        or (
            reference.byte_length > 1
            and (
                type(page.next_cursor) is not str
                or not page.next_cursor
            )
        )
    ):
        raise ProviderOutputIntegrityError(
            "provider output artifact verification failed"
        )
