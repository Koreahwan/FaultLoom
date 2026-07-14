from __future__ import annotations

from typing import NoReturn, final

from ._errors import ProviderOutputIntegrityError


@final
class ProviderOutputCursorKey:
    __slots__ = ("__material",)
    __material: bytes

    def __init__(self, material: bytes) -> None:
        if type(material) is not bytes or len(material) != 32:
            raise ValueError("provider output cursor key must be exactly 32 bytes")
        self.__material = bytes(material)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_ProviderOutputCursorKey__material":
            try:
                object.__getattribute__(self, name)
            except AttributeError:
                object.__setattr__(self, name, value)
                return
        raise AttributeError("ProviderOutputCursorKey is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputCursorKey is immutable")

    def _copy_for_hmac(self) -> bytes:
        material = object.__getattribute__(
            self,
            "_ProviderOutputCursorKey__material",
        )
        if type(material) is not bytes or len(material) != 32:
            raise ProviderOutputIntegrityError(
                "provider output cursor key integrity failed"
            )
        return bytes(material)

    def __repr__(self) -> str:
        return "ProviderOutputCursorKey(<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderOutputCursorKey cannot be serialized")


@final
class ProviderOutputPage:
    __slots__ = ("__data", "__next_cursor", "__offset", "__total_bytes")
    __data: bytes
    __next_cursor: str | None
    __offset: int
    __total_bytes: int

    def __init__(
        self,
        data: bytes,
        *,
        offset: int,
        total_bytes: int,
        next_cursor: str | None,
    ) -> None:
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
        self.__data = bytes(data)
        self.__offset = offset
        self.__total_bytes = total_bytes
        self.__next_cursor = next_cursor

    def __setattr__(self, name: str, value: object) -> None:
        private_names = {
            "_ProviderOutputPage__data",
            "_ProviderOutputPage__next_cursor",
            "_ProviderOutputPage__offset",
            "_ProviderOutputPage__total_bytes",
        }
        if name in private_names:
            try:
                object.__getattribute__(self, name)
            except AttributeError:
                object.__setattr__(self, name, value)
                return
        raise AttributeError("ProviderOutputPage is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputPage is immutable")

    @property
    def data(self) -> bytes:
        return bytes(
            object.__getattribute__(self, "_ProviderOutputPage__data")
        )

    @property
    def offset(self) -> int:
        return object.__getattribute__(self, "_ProviderOutputPage__offset")

    @property
    def total_bytes(self) -> int:
        return object.__getattribute__(self, "_ProviderOutputPage__total_bytes")

    @property
    def next_cursor(self) -> str | None:
        return object.__getattribute__(self, "_ProviderOutputPage__next_cursor")

    def __repr__(self) -> str:
        return (
            "ProviderOutputPage(data=<redacted>, "
            f"offset={self.offset}, total_bytes={self.total_bytes}, "
            f"has_next={self.next_cursor is not None})"
        )

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderOutputPage cannot be serialized")
