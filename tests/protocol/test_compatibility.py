from __future__ import annotations

import pytest

from faultloom_protocol import (
    PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_RANGE,
    SemVer,
    is_protocol_compatible,
    protocol_range_contains,
    require_protocol_compatible,
)


def test_current_protocol_is_compatible_with_declared_range() -> None:
    assert PROTOCOL_VERSION == "0.1.0"
    assert SUPPORTED_PROTOCOL_RANGE == ">=0.1.0,<0.2.0"
    assert is_protocol_compatible(PROTOCOL_VERSION)
    assert is_protocol_compatible("0.1.99")
    assert not is_protocol_compatible("0.2.0")
    assert not is_protocol_compatible("0.0.9")


def test_semver_parser_is_stable_release_only() -> None:
    assert SemVer.parse("1.2.3") < SemVer.parse("1.3.0")
    for invalid in ("1.2", "v1.2.3", "1.2.3-rc1", "01.2.3"):
        with pytest.raises(ValueError, match="semantic version"):
            SemVer.parse(invalid)
    with pytest.raises(ValueError, match="signed int64"):
        SemVer.parse(f"{2**63}.0.0")


def test_protocol_range_parser_fails_closed() -> None:
    assert protocol_range_contains("0.1.5", ">=0.1.0,<0.2.0")
    with pytest.raises(ValueError, match="comparator"):
        protocol_range_contains("0.1.0", "~0.1")
    with pytest.raises(ValueError, match="at least one"):
        protocol_range_contains("0.1.0", "")
    with pytest.raises(ValueError, match="outside supported range"):
        require_protocol_compatible("1.0.0")
