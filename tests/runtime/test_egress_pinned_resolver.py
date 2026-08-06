from __future__ import annotations

import socket
from dataclasses import FrozenInstanceError
from typing import Literal

import pytest
from faultloom.egress import (
    DestinationResolution,
    EgressPlane,
    PinnedDestinationResolver,
)
from faultloom_protocol import SCHEMA_VERSION
from pydantic import ValidationError


def _resolution(
    *,
    origin: str = "https://provider.example.invalid",
    plane: Literal[EgressPlane.MODEL_PROVIDER, EgressPlane.KNOWLEDGE] = (
        EgressPlane.MODEL_PROVIDER
    ),
    addresses: tuple[str, ...] = ("8.8.8.8",),
) -> DestinationResolution:
    return DestinationResolution(
        schema_version=SCHEMA_VERSION,
        plane=plane,
        origin=origin,
        addresses=addresses,
    )


def test_pinned_resolver_returns_fresh_snapshot_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _resolution()
    second = _resolution(
        origin="https://knowledge.example.invalid",
        addresses=("1.1.1.1",),
    )

    def deny_dns(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("pinned resolver must not perform DNS")

    monkeypatch.setattr(socket, "getaddrinfo", deny_dns)
    resolver = PinnedDestinationResolver((second, first))
    same_content = PinnedDestinationResolver((first, second))
    changed_content = PinnedDestinationResolver(
        (_resolution(addresses=("9.9.9.9",)), second)
    )
    resolved = resolver.resolve(first.origin)

    assert resolver.plane is EgressPlane.MODEL_PROVIDER
    assert resolver.resolver_id == same_content.resolver_id
    assert resolver.resolver_id != changed_content.resolver_id
    assert resolved == first
    assert resolved is not first
    with pytest.raises(ValidationError):
        first.addresses = ("4.4.4.4",)
    with pytest.raises(FrozenInstanceError):
        resolver.resolver_id = "resolver.changed"
    object.__setattr__(first, "addresses", ("4.4.4.4",))
    assert resolver.resolve(first.origin).addresses == ("8.8.8.8",)
    object.__setattr__(resolved, "addresses", ("9.9.9.9",))
    assert resolver.resolve(first.origin).addresses == ("8.8.8.8",)


@pytest.mark.parametrize(
    ("snapshots", "message"),
    (
        ((), "at least one"),
        (
            (
                _resolution(),
                _resolution(addresses=("1.1.1.1",)),
            ),
            "origins must be unique",
        ),
        (
            (
                _resolution(),
                _resolution(
                    origin="https://knowledge.example.invalid",
                    plane=EgressPlane.KNOWLEDGE,
                ),
            ),
            "one egress plane",
        ),
    ),
)
def test_pinned_resolver_rejects_invalid_snapshot_sets(
    snapshots: tuple[DestinationResolution, ...], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _ = PinnedDestinationResolver(snapshots)


def test_pinned_resolver_rejects_unknown_or_nonexact_origin() -> None:
    resolver = PinnedDestinationResolver((_resolution(),))

    class OriginSubclass(str):
        pass

    with pytest.raises(ValueError, match="not configured"):
        _ = resolver.resolve("https://other.example.invalid")
    with pytest.raises(TypeError, match="exact string"):
        _ = resolver.resolve(OriginSubclass("https://provider.example.invalid"))


def test_pinned_resolver_identity_normalizes_address_sets_only() -> None:
    expanded = _resolution(
        addresses=("2001:0db8:0000:0000:0000:0000:0000:0001", "8.8.8.8")
    )
    compressed = _resolution(addresses=("8.8.8.8", "2001:db8::1"))

    expanded_resolver = PinnedDestinationResolver((expanded,))
    compressed_resolver = PinnedDestinationResolver((compressed,))

    assert expanded_resolver.resolver_id == compressed_resolver.resolver_id
    assert expanded_resolver.resolve(expanded.origin).addresses == expanded.addresses
