from __future__ import annotations

from typing import NamedTuple

from ._receipt import ProviderReceiptVerifier
from ._store import ProviderOutputStoreBinding
from .contracts import ProviderOutputIntegrityError


class ReaderAdmission(NamedTuple):
    binding: ProviderOutputStoreBinding
    cursor_key: bytes
    maximum_page_bytes: int
    verifier: ProviderReceiptVerifier


def trusted_reader_admission(
    value: object,
    *,
    maximum_page_bytes: int,
) -> ReaderAdmission:
    if (
        type(value) is not ReaderAdmission
        or type(value.binding) is not ProviderOutputStoreBinding
        or type(value.cursor_key) is not bytes
        or len(value.cursor_key) != 32
        or type(value.maximum_page_bytes) is not int
        or not 1 <= value.maximum_page_bytes <= maximum_page_bytes
        or type(value.verifier) is not ProviderReceiptVerifier
    ):
        raise ProviderOutputIntegrityError(
            "provider output reader admission changed"
        )
    ProviderOutputStoreBinding.validate(value.binding)
    return value
