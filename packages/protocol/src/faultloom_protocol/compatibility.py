"""Small dependency-free SemVer compatibility checks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_RANGE

_SEMVER = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)$"
)
_COMPARATOR = re.compile(r"^(>=|<=|>|<|==)(.+)$")


@dataclass(frozen=True, order=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: str) -> "SemVer":
        match = _SEMVER.fullmatch(value)
        if match is None:
            raise ValueError(f"invalid stable semantic version: {value!r}")
        return cls(*(int(match.group(name)) for name in ("major", "minor", "patch")))


def protocol_range_contains(version: str, version_range: str) -> bool:
    candidate = SemVer.parse(version)
    clauses = [clause.strip() for clause in version_range.split(",") if clause.strip()]
    if not clauses:
        raise ValueError("protocol range must contain at least one comparator")
    for clause in clauses:
        match = _COMPARATOR.fullmatch(clause)
        if match is None:
            raise ValueError(f"invalid protocol comparator: {clause!r}")
        operator, raw_bound = match.groups()
        bound = SemVer.parse(raw_bound)
        comparison = {
            ">=": candidate >= bound,
            "<=": candidate <= bound,
            ">": candidate > bound,
            "<": candidate < bound,
            "==": candidate == bound,
        }[operator]
        if not comparison:
            return False
    return True


def is_protocol_compatible(
    peer_version: str,
    supported_range: str = SUPPORTED_PROTOCOL_RANGE,
) -> bool:
    return protocol_range_contains(peer_version, supported_range)


def require_protocol_compatible(
    peer_version: str,
    supported_range: str = SUPPORTED_PROTOCOL_RANGE,
) -> None:
    if not is_protocol_compatible(peer_version, supported_range):
        raise ValueError(
            f"protocol {peer_version} is outside supported range {supported_range} "
            f"for local protocol {PROTOCOL_VERSION}"
        )
