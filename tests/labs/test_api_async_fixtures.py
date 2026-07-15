from __future__ import annotations

from labs.api_async import (
    AsyncSurfaceKind,
    FixturePolarity,
    load_all_api_async_manifests,
)


def test_each_api_async_surface_has_a_loopback_positive_and_negative_fixture() -> None:
    manifests = load_all_api_async_manifests()

    assert {item.surface_kind for item in manifests} == set(AsyncSurfaceKind)
    assert all(item.bind_host == "127.0.0.1" for item in manifests)
    assert all(
        {variant.polarity for variant in item.variants}
        == {FixturePolarity.POSITIVE, FixturePolarity.NEGATIVE}
        for item in manifests
    )
    assert all(item.namespace.startswith("faultloom.lab.api_async.") for item in manifests)
