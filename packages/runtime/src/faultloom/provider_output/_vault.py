from __future__ import annotations

from collections.abc import Callable
from threading import RLock
from typing import TypeVar
from weakref import ReferenceType, ref

from ._errors import ProviderOutputIntegrityError

_Value = TypeVar("_Value")
_Owner = TypeVar("_Owner")


def identity_vault(
    label: str,
) -> tuple[
    Callable[[_Owner, _Value], None],
    Callable[[_Owner], _Value],
]:
    entries: dict[
        int,
        tuple[ReferenceType[_Owner], type[_Owner], _Value],
    ] = {}
    lock = RLock()

    def bind(owner: _Owner, value: _Value) -> None:
        key = id(owner)

        def discard(
            owner_ref: ReferenceType[_Owner],
            *,
            identity: int = key,
        ) -> None:
            with lock:
                current = entries.get(identity)
                if (
                    current is not None
                    and current[0] is owner_ref
                    and owner_ref() is None
                ):
                    entries.pop(identity, None)

        try:
            owner_ref = ref(owner, discard)
        except TypeError as exc:
            raise ProviderOutputIntegrityError(
                f"{label} does not support identity binding"
            ) from exc
        with lock:
            current = entries.get(key)
            if current is not None and current[0]() is owner:
                raise ProviderOutputIntegrityError(
                    f"{label} is already initialized"
                )
            entries[key] = (owner_ref, type(owner), value)

    def read(owner: _Owner) -> _Value:
        with lock:
            current = entries.get(id(owner))
            if current is None or current[0]() is not owner:
                raise ProviderOutputIntegrityError(
                    f"{label} identity binding is unavailable"
                )
            if type(owner) is not current[1]:
                raise ProviderOutputIntegrityError(
                    f"{label} runtime type changed"
                )
            return current[2]

    return bind, read
