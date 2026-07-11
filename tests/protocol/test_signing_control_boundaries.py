from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo

import pytest

from faultloom_protocol import (
    AuthoritySigner,
    SignatureExpiredError,
    sign_authority_grant,
    sign_engagement_bundle,
    sign_run_result_bundle,
    sign_scope_epoch,
    verify_authority_grant,
    verify_engagement_bundle,
    verify_run_result_bundle,
    verify_scope_epoch,
)

from .factories import NOW, sample_models


class MaliciousDatetime(datetime):
    def __bool__(self) -> bool:
        raise AssertionError("datetime subclass truthiness must not run")

    def __add__(self, other: object) -> "MaliciousDatetime":
        return self

    def __lt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return False


class MatchEverything(str):
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class MaliciousInt(int):
    def __lt__(self, other: object) -> bool:
        raise AssertionError("int subclass comparison must not run")

    def __le__(self, other: object) -> bool:
        raise AssertionError("int subclass comparison must not run")


class MaliciousTimedelta(timedelta):
    def __radd__(self, other: object) -> object:
        raise AssertionError("timedelta subclass arithmetic must not run")


class StatefulTimezone(tzinfo):
    def __init__(self) -> None:
        self.magic_calls = 0

    def _reject(self) -> None:
        self.magic_calls += 1
        raise AssertionError("caller-controlled timezone hooks must not run")

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self._reject()

    def dst(self, dt: datetime | None) -> timedelta:
        self._reject()

    def tzname(self, dt: datetime | None) -> str:
        self._reject()

    def fromutc(self, dt: datetime) -> datetime:
        self._reject()


def _expired_datetime_subclass() -> MaliciousDatetime:
    expired = NOW + timedelta(hours=3)
    return MaliciousDatetime(
        expired.year,
        expired.month,
        expired.day,
        expired.hour,
        expired.minute,
        expired.second,
        expired.microsecond,
        tzinfo=timezone.utc,
    )


def test_datetime_subclass_is_rejected_before_authority_scope_or_bundle_logic() -> None:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    grant = sign_authority_grant(
        models["AuthorityGrant"], authority_signer, signed_at=NOW
    )
    epoch = sign_scope_epoch(models["ScopeEpoch"], authority_signer, signed_at=NOW)
    bundle = sign_engagement_bundle(
        models["EngagementBundle"], outer_signer, signed_at=NOW
    )
    result = models["RunResultBundle"]
    result_signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    signed_result = sign_run_result_bundle(result, result_signer, signed_at=NOW)
    evil = _expired_datetime_subclass()

    with pytest.raises(ValueError, match="exact datetime"):
        verify_authority_grant(grant, authority_signer.public_key_record, now=evil)
    with pytest.raises(ValueError, match="exact datetime"):
        verify_scope_epoch(epoch, authority_signer.public_key_record, now=evil)
    with pytest.raises(ValueError, match="exact datetime"):
        verify_engagement_bundle(
            bundle,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=evil,
        )
    with pytest.raises(ValueError, match="exact datetime"):
        verify_run_result_bundle(
            signed_result,
            result_signer.public_key_record,
            now=evil,
            expected_run_id=result.run_id,
            expected_run_manifest_digest=result.run_manifest_digest,
            expected_authority_digest=result.authority_digest,
        )


def test_bundle_verifiers_preserve_ordinary_expiry_boundaries() -> None:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    engagement = models["EngagementBundle"]
    signed_engagement = sign_engagement_bundle(
        engagement, outer_signer, signed_at=NOW
    )
    result = models["RunResultBundle"]
    result_signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    result_expiry = NOW + timedelta(hours=1)
    signed_result = sign_run_result_bundle(
        result,
        result_signer,
        signed_at=NOW,
        expires_at=result_expiry,
    )

    with pytest.raises(SignatureExpiredError, match="expired"):
        verify_engagement_bundle(
            signed_engagement,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=engagement.expires_at,
        )
    with pytest.raises(SignatureExpiredError, match="expired"):
        verify_run_result_bundle(
            signed_result,
            result_signer.public_key_record,
            now=result_expiry,
            expected_run_id=result.run_id,
            expected_run_manifest_digest=result.run_manifest_digest,
            expected_authority_digest=result.authority_digest,
        )


def test_exact_datetime_with_caller_controlled_timezone_is_rejected_without_hooks() -> None:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    result_signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    grant = sign_authority_grant(
        models["AuthorityGrant"], authority_signer, signed_at=NOW
    )
    epoch = sign_scope_epoch(models["ScopeEpoch"], authority_signer, signed_at=NOW)
    engagement = sign_engagement_bundle(
        models["EngagementBundle"], outer_signer, signed_at=NOW
    )
    result = models["RunResultBundle"]
    signed_result = sign_run_result_bundle(result, result_signer, signed_at=NOW)
    hostile_timezone = StatefulTimezone()
    hostile_now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=hostile_timezone)
    calls = (
        lambda: verify_authority_grant(
            grant, authority_signer.public_key_record, now=hostile_now
        ),
        lambda: verify_scope_epoch(
            epoch, authority_signer.public_key_record, now=hostile_now
        ),
        lambda: verify_engagement_bundle(
            engagement,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=hostile_now,
        ),
        lambda: verify_run_result_bundle(
            signed_result,
            result_signer.public_key_record,
            now=hostile_now,
            expected_run_id=result.run_id,
            expected_run_manifest_digest=result.run_manifest_digest,
            expected_authority_digest=result.authority_digest,
        ),
    )

    for call in calls:
        with pytest.raises(ValueError, match="timezone.utc"):
            call()
        assert hostile_timezone.magic_calls == 0


def test_expected_identifier_subclasses_cannot_override_authority_bindings() -> None:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    grant = sign_authority_grant(
        models["AuthorityGrant"], authority_signer, signed_at=NOW
    )
    epoch = sign_scope_epoch(models["ScopeEpoch"], authority_signer, signed_at=NOW)
    bundle = sign_engagement_bundle(
        models["EngagementBundle"], outer_signer, signed_at=NOW
    )
    wrong = MatchEverything("attacker.control")

    with pytest.raises(ValueError, match="expected_grant_id.*exact string"):
        verify_authority_grant(
            grant,
            authority_signer.public_key_record,
            now=NOW,
            expected_grant_id=wrong,
        )
    with pytest.raises(ValueError, match="expected_grant_id.*exact string"):
        verify_scope_epoch(
            epoch,
            authority_signer.public_key_record,
            now=NOW,
            expected_grant_id=wrong,
        )
    with pytest.raises(ValueError, match="expected_engagement_id.*exact string"):
        verify_engagement_bundle(
            bundle,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
            expected_engagement_id=wrong,
        )
    with pytest.raises(ValueError, match="expected_grant_id.*exact string"):
        verify_engagement_bundle(
            bundle,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
            expected_grant_id=wrong,
        )


@pytest.mark.parametrize(
    "field",
    [
        "expected_engagement_id",
        "expected_run_id",
        "expected_run_manifest_digest",
        "expected_authority_digest",
    ],
)
def test_result_expected_string_subclasses_cannot_override_bindings(field: str) -> None:
    result = sample_models()["RunResultBundle"]
    signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    envelope = sign_run_result_bundle(result, signer, signed_at=NOW)
    controls: dict[str, str] = {
        "expected_engagement_id": result.engagement_id,
        "expected_run_id": result.run_id,
        "expected_run_manifest_digest": result.run_manifest_digest,
        "expected_authority_digest": result.authority_digest,
    }
    controls[field] = MatchEverything("attacker.control")

    with pytest.raises(ValueError, match=rf"{field}.*exact string"):
        verify_run_result_bundle(
            envelope,
            signer.public_key_record,
            now=NOW,
            **controls,
        )


@pytest.mark.parametrize("bad_minimum", [True, MaliciousInt(1)])
def test_every_minimum_sequence_control_requires_an_exact_int(
    bad_minimum: object,
) -> None:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    result_signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    grant = sign_authority_grant(
        models["AuthorityGrant"], authority_signer, signed_at=NOW
    )
    epoch = sign_scope_epoch(models["ScopeEpoch"], authority_signer, signed_at=NOW)
    bundle = sign_engagement_bundle(
        models["EngagementBundle"], outer_signer, signed_at=NOW
    )
    result = models["RunResultBundle"]
    signed_result = sign_run_result_bundle(result, result_signer, signed_at=NOW)
    calls = (
        lambda: verify_authority_grant(
            grant,
            authority_signer.public_key_record,
            now=NOW,
            minimum_version=bad_minimum,  # type: ignore[arg-type]
        ),
        lambda: verify_scope_epoch(
            epoch,
            authority_signer.public_key_record,
            now=NOW,
            minimum_epoch=bad_minimum,  # type: ignore[arg-type]
        ),
        lambda: verify_engagement_bundle(
            bundle,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
            minimum_version=bad_minimum,  # type: ignore[arg-type]
        ),
        lambda: verify_engagement_bundle(
            bundle,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
            minimum_authority_version=bad_minimum,  # type: ignore[arg-type]
        ),
        lambda: verify_run_result_bundle(
            signed_result,
            result_signer.public_key_record,
            now=NOW,
            minimum_version=bad_minimum,  # type: ignore[arg-type]
            expected_run_id=result.run_id,
            expected_run_manifest_digest=result.run_manifest_digest,
            expected_authority_digest=result.authority_digest,
        ),
    )

    for call in calls:
        with pytest.raises(ValueError, match="minimum trusted sequence"):
            call()


@pytest.mark.parametrize(
    "bad_skew",
    [MaliciousTimedelta(0), timedelta(microseconds=-1)],
)
def test_every_verifier_requires_an_exact_non_negative_clock_skew(
    bad_skew: object,
) -> None:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    result_signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    grant = sign_authority_grant(
        models["AuthorityGrant"], authority_signer, signed_at=NOW
    )
    epoch = sign_scope_epoch(models["ScopeEpoch"], authority_signer, signed_at=NOW)
    bundle = sign_engagement_bundle(
        models["EngagementBundle"], outer_signer, signed_at=NOW
    )
    result = models["RunResultBundle"]
    signed_result = sign_run_result_bundle(result, result_signer, signed_at=NOW)
    calls = (
        lambda: verify_authority_grant(
            grant,
            authority_signer.public_key_record,
            now=NOW,
            maximum_clock_skew=bad_skew,  # type: ignore[arg-type]
        ),
        lambda: verify_scope_epoch(
            epoch,
            authority_signer.public_key_record,
            now=NOW,
            maximum_clock_skew=bad_skew,  # type: ignore[arg-type]
        ),
        lambda: verify_engagement_bundle(
            bundle,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
            maximum_clock_skew=bad_skew,  # type: ignore[arg-type]
        ),
        lambda: verify_run_result_bundle(
            signed_result,
            result_signer.public_key_record,
            now=NOW,
            expected_run_id=result.run_id,
            expected_run_manifest_digest=result.run_manifest_digest,
            expected_authority_digest=result.authority_digest,
            maximum_clock_skew=bad_skew,  # type: ignore[arg-type]
        ),
    )

    for call in calls:
        with pytest.raises(ValueError, match="exact non-negative timedelta"):
            call()
