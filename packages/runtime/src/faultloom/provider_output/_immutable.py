from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, NamedTuple, NoReturn, final
from weakref import ReferenceType

from ._errors import ProviderOutputIntegrityError
from ._vault import identity_vault

_cursor_vault: tuple[
    Callable[[ProviderOutputCursorKey, bytes], None],
    Callable[[ProviderOutputCursorKey], bytes],
] = identity_vault("provider output cursor key")
_bind_cursor, _read_cursor = _cursor_vault


@final
class ProviderOutputCursorKey:
    __slots__ = ("__weakref__",)

    def __init_subclass__(cls) -> None:
        raise ProviderOutputIntegrityError("ProviderOutputCursorKey is final")

    def __init__(self, material: bytes) -> None:
        if TYPE_CHECKING:
            self.__weakref__: ReferenceType[ProviderOutputCursorKey] | None = None
        if type(material) is not bytes or len(material) != 32:
            raise ValueError("provider output cursor key must be exactly 32 bytes")
        _bind_cursor(self, bytes(material))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ProviderOutputCursorKey is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputCursorKey is immutable")

    def _copy_for_hmac(self) -> bytes:
        material = _read_cursor(self)
        if type(material) is not bytes or len(material) != 32:
            raise ProviderOutputIntegrityError(
                "provider output cursor key integrity failed"
            )
        return bytes(material)

    def __repr__(self) -> str:
        return "ProviderOutputCursorKey(<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderOutputCursorKey cannot be serialized")


class _PageValue(NamedTuple):
    data: bytes
    next_cursor: str | None
    offset: int
    total_bytes: int


_page_vault: tuple[
    Callable[[ProviderOutputPage, _PageValue], None],
    Callable[[ProviderOutputPage], _PageValue],
] = identity_vault("provider output page")
_bind_page, _read_page = _page_vault


@final
class ProviderOutputPage:
    __slots__ = ("__weakref__",)

    def __init_subclass__(cls) -> None:
        raise ProviderOutputIntegrityError("ProviderOutputPage is final")

    def __init__(
        self,
        data: bytes,
        *,
        offset: int,
        total_bytes: int,
        next_cursor: str | None,
    ) -> None:
        if TYPE_CHECKING:
            self.__weakref__: ReferenceType[ProviderOutputPage] | None = None
        if type(data) is not bytes:
            raise TypeError("provider output page data must be exact bytes")
        if (
            type(offset) is not int
            or type(total_bytes) is not int
            or offset < 0
            or total_bytes < 0
            or offset + len(data) > total_bytes
        ):
            raise ValueError("provider output page bounds are invalid")
        if next_cursor is not None and (
            type(next_cursor) is not str or not next_cursor
        ):
            raise ValueError("provider output continuation cursor is invalid")
        _bind_page(
            self,
            _PageValue(bytes(data), next_cursor, offset, total_bytes),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ProviderOutputPage is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputPage is immutable")

    def _trusted_value(self) -> _PageValue:
        value = _read_page(self)
        if (
            type(value) is not _PageValue
            or type(value.data) is not bytes
            or type(value.offset) is not int
            or type(value.total_bytes) is not int
            or value.offset < 0
            or value.total_bytes < 0
            or value.offset + len(value.data) > value.total_bytes
            or (
                value.next_cursor is not None
                and (
                    type(value.next_cursor) is not str
                    or not value.next_cursor
                )
            )
        ):
            raise ProviderOutputIntegrityError(
                "provider output page identity binding changed"
            )
        return value

    @property
    def data(self) -> bytes:
        return bytes(self._trusted_value().data)

    @property
    def offset(self) -> int:
        return self._trusted_value().offset

    @property
    def total_bytes(self) -> int:
        return self._trusted_value().total_bytes

    @property
    def next_cursor(self) -> str | None:
        return self._trusted_value().next_cursor

    def __repr__(self) -> str:
        return (
            "ProviderOutputPage(data=<redacted>, "
            f"offset={self.offset}, total_bytes={self.total_bytes}, "
            f"has_next={self.next_cursor is not None})"
        )

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderOutputPage cannot be serialized")
