from __future__ import annotations

from datetime import datetime, timezone

import pytest

from faultloom_protocol import canonical_json, canonical_json_bytes, sha256_digest


def test_canonical_json_is_sorted_compact_utf8_and_utc() -> None:
    value = {
        "z": "한글",
        "a": datetime(2030, 1, 2, 12, 4, 5, 6, tzinfo=timezone.utc),
        "list": (True, None, 7),
    }
    expected = (
        '{"a":"2030-01-02T12:04:05.000006Z","list":[true,null,7],"z":"한글"}'
    )
    assert canonical_json(value) == expected
    assert canonical_json_bytes(value) == expected.encode("utf-8")


def test_datetime_offsets_normalize_to_same_digest() -> None:
    utc = datetime.fromisoformat("2030-01-02T03:04:05.678901+00:00")
    korea = datetime.fromisoformat("2030-01-02T12:04:05.678901+09:00")
    assert sha256_digest({"at": utc}) == sha256_digest({"at": korea})


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf")])
def test_canonical_json_forbids_floating_point(value: float) -> None:
    with pytest.raises(TypeError, match="floating-point"):
        canonical_json_bytes({"value": value})


def test_canonical_json_forbids_naive_datetime_and_binary() -> None:
    with pytest.raises(ValueError, match="naive datetime"):
        canonical_json_bytes({"at": datetime(2030, 1, 1)})
    with pytest.raises(TypeError, match="unsupported"):
        canonical_json_bytes({"bytes": b"not-json"})


@pytest.mark.parametrize("value", [-(2**63) - 1, 2**63])
def test_canonical_json_forbids_integers_outside_signed_64_bit(value: int) -> None:
    with pytest.raises(ValueError, match="signed 64-bit"):
        canonical_json_bytes({"value": value})


@pytest.mark.parametrize(
    "field",
    ["password", "Cookie", "authorization", "api-key", "private_key", "accessToken"],
)
def test_canonical_json_rejects_raw_secret_shaped_keys(field: str) -> None:
    with pytest.raises(ValueError, match="raw secret field"):
        canonical_json_bytes({field: "do-not-sign"})


def test_canonical_digest_is_order_independent() -> None:
    left = {"b": 2, "a": {"y": 2, "x": 1}}
    right = {"a": {"x": 1, "y": 2}, "b": 2}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert sha256_digest(left) == sha256_digest(right)
