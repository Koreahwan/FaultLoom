from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Callable, ClassVar

import pytest

import faultloom_protocol.signing as signing_module
from faultloom_protocol import (
    AuthorityGrant,
    AuthorityRevokedError,
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    EngagementBundle,
    GatewayEpochReceiptIssuer,
    RunResultBundle,
    ScopeEpoch,
    SignatureBlock,
    SignatureExpiredError,
    SignatureNotYetValidError,
    SignaturePurpose,
    SignatureRollbackError,
    SignatureTamperError,
    SignedAuthorityGrant,
    SignedEngagementBundle,
    SignedRunResultBundle,
    SignedScopeEpoch,
    UnknownKeyError,
    canonical_json_bytes,
    sign_authority_grant,
    sign_engagement_bundle,
    sign_run_result_bundle,
    sign_scope_epoch,
    signing_bytes,
    verify_authority_grant,
    verify_engagement_bundle,
    verify_run_result_bundle,
    verify_scope_epoch,
)

from .factories import LATER, NOW, sample_models


class ExpiryBypassDatetime(datetime):
    comparison_calls: ClassVar[int] = 0

    @classmethod
    def from_datetime(cls, value: datetime) -> "ExpiryBypassDatetime":
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            tzinfo=value.tzinfo,
            fold=value.fold,
        )

    def __le__(self, other: object) -> bool:
        type(self).comparison_calls += 1
        return False


class FutureBypassDatetime(datetime):
    comparison_calls: ClassVar[int] = 0

    @classmethod
    def from_datetime(cls, value: datetime) -> "FutureBypassDatetime":
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            tzinfo=value.tzinfo,
            fold=value.fold,
        )

    def __gt__(self, other: object) -> bool:
        type(self).comparison_calls += 1
        return False


class HostileDatetime(datetime):
    hook_calls: ClassVar[int] = 0

    def _hook(self) -> None:
        type(self).hook_calls += 1
        raise AssertionError("datetime hook executed")

    def __bool__(self) -> bool:
        self._hook()

    def __add__(self, other: object) -> object:
        self._hook()

    def __lt__(self, other: object) -> bool:
        self._hook()

    def __ge__(self, other: object) -> bool:
        self._hook()


class HostileTimezone(tzinfo):
    def __init__(self) -> None:
        self.hook_calls = 0

    def _hook(self) -> None:
        self.hook_calls += 1
        raise AssertionError("timezone hook executed")

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self._hook()

    def dst(self, dt: datetime | None) -> timedelta:
        self._hook()

    def tzname(self, dt: datetime | None) -> str:
        self._hook()

    def fromutc(self, dt: datetime) -> datetime:
        self._hook()


class MatchAnyKeyId(str):
    comparison_calls: ClassVar[int] = 0

    def __eq__(self, other: object) -> bool:
        type(self).comparison_calls += 1
        return True

    def __ne__(self, other: object) -> bool:
        type(self).comparison_calls += 1
        return False


class BindingBypassStr(str):
    hook_calls: ClassVar[int] = 0

    def __eq__(self, other: object) -> bool:
        type(self).hook_calls += 1
        return True

    def __ne__(self, other: object) -> bool:
        type(self).hook_calls += 1
        return False

    __hash__ = str.__hash__


class RollbackBypassInt(int):
    hook_calls: ClassVar[int] = 0

    def __lt__(self, other: object) -> bool:
        type(self).hook_calls += 1
        return False


class HostileBytes(bytes):
    hook_calls: ClassVar[int] = 0

    def __len__(self) -> int:
        type(self).hook_calls += 1
        raise AssertionError("bytes hook executed")

    def __iter__(self):  # type: ignore[no-untyped-def]
        type(self).hook_calls += 1
        raise AssertionError("bytes hook executed")


class HostileUnsupportedValue:
    hook_calls: ClassVar[int] = 0

    def _hook(self) -> None:
        type(self).hook_calls += 1
        raise AssertionError("unsupported-value hook executed")

    def __repr__(self) -> str:
        self._hook()

    def __str__(self) -> str:
        self._hook()

    def __eq__(self, other: object) -> bool:
        self._hook()


class HostileEnumValue(str):
    hook_calls: ClassVar[int] = 0

    def _hook(self) -> None:
        type(self).hook_calls += 1
        raise AssertionError("counterfeit-enum value hook executed")

    def __repr__(self) -> str:
        self._hook()

    def __str__(self) -> str:
        self._hook()

    def __eq__(self, other: object) -> bool:
        self._hook()

    def __hash__(self) -> int:
        self._hook()


class HookedAuthorityEnvelope(SignedAuthorityGrant):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AssertionError("authority envelope model_dump hook executed")


class HookedScopeEnvelope(SignedScopeEpoch):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AssertionError("scope envelope model_dump hook executed")


class HookedEngagementEnvelope(SignedEngagementBundle):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AssertionError("engagement envelope model_dump hook executed")


class HookedResultEnvelope(SignedRunResultBundle):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AssertionError("result envelope model_dump hook executed")


class HookedScopePayload(ScopeEpoch):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AssertionError("scope payload model_dump hook executed")


class HostileModelMetaclass(type(ScopeEpoch)):
    metadata_hook_calls: ClassVar[int] = 0

    def __getattribute__(cls, name: str) -> object:
        if name in {"__module__", "__name__"}:
            type(cls).metadata_hook_calls += 1
        return type.__getattribute__(cls, name)


class MetaclassHookedScopePayload(
    ScopeEpoch,
    metaclass=HostileModelMetaclass,
):
    pass


class HookedSignatureBlock(SignatureBlock):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AssertionError("signature model_dump hook executed")


class RevocationSignalKeyRecord(Ed25519PublicKeyRecord):
    hook_calls: ClassVar[int] = 0

    def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
        type(self).hook_calls += 1
        raise AuthorityRevokedError("injected by key serialization")


def _state() -> dict[str, object]:
    models = sample_models()
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    result_signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    attacker_signer = AuthoritySigner.from_private_bytes(bytes([9]) * 32)
    return {
        "grant": models["AuthorityGrant"],
        "epoch": models["ScopeEpoch"],
        "engagement": models["EngagementBundle"],
        "result": models["RunResultBundle"],
        "authority_signer": authority_signer,
        "outer_signer": outer_signer,
        "result_signer": result_signer,
        "attacker_signer": attacker_signer,
    }


def _verification_calls(
    *,
    authority: SignedAuthorityGrant,
    scope: SignedScopeEpoch,
    engagement: SignedEngagementBundle,
    result: SignedRunResultBundle,
    now: datetime,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> tuple[Callable[[], object], ...]:
    state = _state()
    grant = state["grant"]
    result_payload = state["result"]
    authority_signer = state["authority_signer"]
    outer_signer = state["outer_signer"]
    result_signer = state["result_signer"]
    assert isinstance(grant, AuthorityGrant)
    assert isinstance(result_payload, RunResultBundle)
    assert isinstance(authority_signer, AuthoritySigner)
    assert isinstance(outer_signer, AuthoritySigner)
    assert isinstance(result_signer, AuthoritySigner)
    return (
        lambda: verify_authority_grant(
            authority,
            authority_signer.public_key_record,
            now=now,
            expected_grant_id=grant.grant_id,
            maximum_clock_skew=maximum_clock_skew,
        ),
        lambda: verify_scope_epoch(
            scope,
            authority_signer.public_key_record,
            now=now,
            expected_grant_id=grant.grant_id,
            maximum_clock_skew=maximum_clock_skew,
        ),
        lambda: verify_engagement_bundle(
            engagement,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=now,
            expected_grant_id=grant.grant_id,
            maximum_clock_skew=maximum_clock_skew,
        ),
        lambda: verify_run_result_bundle(
            result,
            result_signer.public_key_record,
            now=now,
            expected_run_id=result_payload.run_id,
            expected_run_manifest_digest=result_payload.run_manifest_digest,
            expected_authority_digest=result_payload.authority_digest,
            maximum_clock_skew=maximum_clock_skew,
        ),
    )


def _signed_state(
    *, result_expiry: datetime | None = None
) -> tuple[
    SignedAuthorityGrant,
    SignedScopeEpoch,
    SignedEngagementBundle,
    SignedRunResultBundle,
]:
    state = _state()
    grant = state["grant"]
    epoch = state["epoch"]
    engagement = state["engagement"]
    result = state["result"]
    authority_signer = state["authority_signer"]
    outer_signer = state["outer_signer"]
    result_signer = state["result_signer"]
    assert isinstance(grant, AuthorityGrant)
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(engagement, EngagementBundle)
    assert isinstance(result, RunResultBundle)
    assert isinstance(authority_signer, AuthoritySigner)
    assert isinstance(outer_signer, AuthoritySigner)
    assert isinstance(result_signer, AuthoritySigner)
    return (
        sign_authority_grant(grant, authority_signer, signed_at=NOW),
        sign_scope_epoch(epoch, authority_signer, signed_at=NOW),
        sign_engagement_bundle(engagement, outer_signer, signed_at=NOW),
        sign_run_result_bundle(
            result,
            result_signer,
            signed_at=NOW,
            expires_at=result_expiry,
        ),
    )


def test_all_public_verifiers_reject_signed_expiry_datetime_subclasses() -> None:
    authority, scope, engagement, result = _signed_state(result_expiry=LATER)
    evil = ExpiryBypassDatetime.from_datetime(LATER)
    authority = authority.model_copy(
        update={
            "payload": authority.payload.model_copy(update={"expires_at": evil}),
            "signature": authority.signature.model_copy(update={"expires_at": evil}),
        }
    )
    scope = scope.model_copy(
        update={
            "payload": scope.payload.model_copy(update={"expires_at": evil}),
            "signature": scope.signature.model_copy(update={"expires_at": evil}),
        }
    )
    engagement = engagement.model_copy(
        update={
            "payload": engagement.payload.model_copy(update={"expires_at": evil}),
            "signature": engagement.signature.model_copy(update={"expires_at": evil}),
        }
    )
    result = result.model_copy(
        update={"signature": result.signature.model_copy(update={"expires_at": evil})}
    )
    ExpiryBypassDatetime.comparison_calls = 0

    for call in _verification_calls(
        authority=authority,
        scope=scope,
        engagement=engagement,
        result=result,
        now=LATER,
    ):
        with pytest.raises(SignatureExpiredError, match="exact datetime"):
            call()
    assert ExpiryBypassDatetime.comparison_calls == 0


def test_all_public_verifiers_reject_signed_future_datetime_subclasses() -> None:
    authority, scope, engagement, result = _signed_state()
    evil = FutureBypassDatetime.from_datetime(NOW)
    authority = authority.model_copy(
        update={"signature": authority.signature.model_copy(update={"signed_at": evil})}
    )
    scope = scope.model_copy(
        update={"signature": scope.signature.model_copy(update={"signed_at": evil})}
    )
    engagement = engagement.model_copy(
        update={"signature": engagement.signature.model_copy(update={"signed_at": evil})}
    )
    result = result.model_copy(
        update={"signature": result.signature.model_copy(update={"signed_at": evil})}
    )
    FutureBypassDatetime.comparison_calls = 0

    for call in _verification_calls(
        authority=authority,
        scope=scope,
        engagement=engagement,
        result=result,
        now=NOW - timedelta(microseconds=1),
        maximum_clock_skew=timedelta(0),
    ):
        with pytest.raises(SignatureNotYetValidError, match="exact datetime"):
            call()
    assert FutureBypassDatetime.comparison_calls == 0


def test_nested_issuance_activation_and_binding_subclasses_fail_without_hooks() -> None:
    authority, scope, engagement, result = _signed_state()
    hostile_time = FutureBypassDatetime.from_datetime(NOW)
    hostile_id = BindingBypassStr("attacker.binding")
    hostile_sequence = RollbackBypassInt(1)
    cases = (
        authority.model_copy(
            update={
                "payload": authority.payload.model_copy(update={"not_before": hostile_time})
            }
        ),
        scope.model_copy(
            update={
                "payload": scope.payload.model_copy(update={"grant_id": hostile_id})
            }
        ),
        engagement.model_copy(
            update={
                "signature": engagement.signature.model_copy(
                    update={"sequence": hostile_sequence}
                )
            }
        ),
        result.model_copy(
            update={
                "payload": result.payload.model_copy(update={"run_id": hostile_id})
            }
        ),
    )
    calls = _verification_calls(
        authority=cases[0],
        scope=cases[1],
        engagement=cases[2],
        result=cases[3],
        now=NOW,
    )
    BindingBypassStr.hook_calls = 0
    RollbackBypassInt.hook_calls = 0
    FutureBypassDatetime.comparison_calls = 0
    expected_errors = (
        SignatureNotYetValidError,
        SignatureTamperError,
        SignatureRollbackError,
        SignatureTamperError,
    )
    for call, expected_error in zip(calls, expected_errors, strict=True):
        with pytest.raises(expected_error, match="exact|validation"):
            call()
    assert BindingBypassStr.hook_calls == 0
    assert RollbackBypassInt.hook_calls == 0
    assert FutureBypassDatetime.comparison_calls == 0


def _forge_key_id(
    envelope: SignedAuthorityGrant
    | SignedScopeEpoch
    | SignedEngagementBundle
    | SignedRunResultBundle,
    attacker: AuthoritySigner,
    victim_key_id: str,
) -> object:
    block = envelope.signature.model_copy(
        update={"key_id": victim_key_id, "signature": "A" * 86}
    )
    block = block.model_copy(
        update={"signature": attacker.sign(signing_bytes(envelope.payload, block))}
    )
    return envelope.model_copy(update={"signature": block})


def test_all_public_verifiers_reject_attacker_key_record_substitution() -> None:
    state = _state()
    grant = state["grant"]
    epoch = state["epoch"]
    engagement_payload = state["engagement"]
    result_payload = state["result"]
    authority_signer = state["authority_signer"]
    outer_signer = state["outer_signer"]
    result_signer = state["result_signer"]
    attacker = state["attacker_signer"]
    assert isinstance(grant, AuthorityGrant)
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(engagement_payload, EngagementBundle)
    assert isinstance(result_payload, RunResultBundle)
    assert isinstance(authority_signer, AuthoritySigner)
    assert isinstance(outer_signer, AuthoritySigner)
    assert isinstance(result_signer, AuthoritySigner)
    assert isinstance(attacker, AuthoritySigner)
    forged = (
        _forge_key_id(
            sign_authority_grant(grant, attacker, signed_at=NOW),
            attacker,
            authority_signer.key_id,
        ),
        _forge_key_id(
            sign_scope_epoch(epoch, attacker, signed_at=NOW),
            attacker,
            authority_signer.key_id,
        ),
        _forge_key_id(
            sign_engagement_bundle(engagement_payload, attacker, signed_at=NOW),
            attacker,
            outer_signer.key_id,
        ),
        _forge_key_id(
            sign_run_result_bundle(result_payload, attacker, signed_at=NOW),
            attacker,
            result_signer.key_id,
        ),
    )
    attacker_record = attacker.public_key_record.model_copy(
        update={"key_id": MatchAnyKeyId(attacker.key_id)}
    )
    MatchAnyKeyId.comparison_calls = 0
    calls = (
        lambda: verify_authority_grant(forged[0], attacker_record, now=NOW),
        lambda: verify_scope_epoch(forged[1], attacker_record, now=NOW),
        lambda: verify_engagement_bundle(
            forged[2],
            attacker_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
        ),
        lambda: verify_run_result_bundle(
            forged[3],
            attacker_record,
            now=NOW,
            expected_run_id=result_payload.run_id,
            expected_run_manifest_digest=result_payload.run_manifest_digest,
            expected_authority_digest=result_payload.authority_digest,
        ),
    )
    for call in calls:
        with pytest.raises((ValueError, UnknownKeyError, SignatureTamperError)):
            call()
    assert MatchAnyKeyId.comparison_calls == 0


def test_exact_outer_envelope_rejects_nested_model_hooks_without_execution() -> None:
    _, scope, _, _ = _signed_state()
    payload = HookedScopePayload.model_validate(scope.payload.model_dump(mode="python"))
    signature = HookedSignatureBlock.model_validate(
        scope.signature.model_dump(mode="python")
    )
    HookedScopePayload.hook_calls = 0
    HookedSignatureBlock.hook_calls = 0
    for envelope in (
        scope.model_copy(update={"payload": payload}),
        scope.model_copy(update={"signature": signature}),
    ):
        assert type(envelope) is SignedScopeEpoch
        with pytest.raises(SignatureTamperError, match="exact protocol model"):
            verify_scope_epoch(
                envelope,
                AuthoritySigner.from_private_bytes(bytes(range(32))).public_key_record,
                now=NOW,
            )
    assert HookedScopePayload.hook_calls == 0
    assert HookedSignatureBlock.hook_calls == 0


def test_exact_outer_rejects_nested_hostile_metaclass_without_metadata_hooks() -> None:
    _, scope, _, _ = _signed_state()
    payload = MetaclassHookedScopePayload.model_validate(
        scope.payload.model_dump(mode="python")
    )
    envelope = scope.model_copy(update={"payload": payload})
    HostileModelMetaclass.metadata_hook_calls = 0

    with pytest.raises(SignatureTamperError, match="exact protocol model"):
        verify_scope_epoch(
            envelope,
            AuthoritySigner.from_private_bytes(bytes(range(32))).public_key_record,
            now=NOW,
        )
    assert HostileModelMetaclass.metadata_hook_calls == 0


def test_all_public_verifiers_reject_outer_envelope_hooks_without_execution() -> None:
    authority, scope, engagement, result = _signed_state()
    hooked = (
        HookedAuthorityEnvelope.model_validate(authority.model_dump(mode="python")),
        HookedScopeEnvelope.model_validate(scope.model_dump(mode="python")),
        HookedEngagementEnvelope.model_validate(
            engagement.model_dump(mode="python")
        ),
        HookedResultEnvelope.model_validate(result.model_dump(mode="python")),
    )
    calls = _verification_calls(
        authority=hooked[0],
        scope=hooked[1],
        engagement=hooked[2],
        result=hooked[3],
        now=NOW,
    )
    envelope_types = (
        HookedAuthorityEnvelope,
        HookedScopeEnvelope,
        HookedEngagementEnvelope,
        HookedResultEnvelope,
    )
    for envelope_type in envelope_types:
        envelope_type.hook_calls = 0
    for call in calls:
        with pytest.raises(ValueError, match="exact protocol model"):
            call()
    assert all(envelope_type.hook_calls == 0 for envelope_type in envelope_types)


def test_corrupt_exact_envelope_storage_maps_to_tamper_without_hooks() -> None:
    _, scope, _, _ = _signed_state()
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    envelope_storage = dict(object.__getattribute__(scope, "__dict__"))

    missing_signature = SignedScopeEpoch.model_construct(
        **{
            key: value
            for key, value in envelope_storage.items()
            if key != "signature"
        }
    )
    extra_field = SignedScopeEpoch.model_construct(**envelope_storage)
    object.__getattribute__(extra_field, "__dict__")["attacker_extra"] = True
    hostile_value = HostileUnsupportedValue()
    payload_storage = dict(object.__getattribute__(scope.payload, "__dict__"))
    poisoned_payload = ScopeEpoch.model_construct(
        **{**payload_storage, "grant_id": hostile_value}
    )
    unsupported_value = SignedScopeEpoch.model_construct(
        **{**envelope_storage, "payload": poisoned_payload}
    )
    cycle: list[object] = []
    cycle.append(cycle)
    cyclic_payload = ScopeEpoch.model_construct(
        **{**payload_storage, "grant_id": cycle}
    )
    cyclic_value = SignedScopeEpoch.model_construct(
        **{**envelope_storage, "payload": cyclic_payload}
    )
    deep_value: object = "grant.1"
    for _ in range(130):
        deep_value = [deep_value]
    deep_payload = ScopeEpoch.model_construct(
        **{**payload_storage, "grant_id": deep_value}
    )
    excessive_depth = SignedScopeEpoch.model_construct(
        **{**envelope_storage, "payload": deep_payload}
    )
    HostileUnsupportedValue.hook_calls = 0

    cases = (
        (missing_signature, "malformed"),
        (extra_field, "malformed"),
        (unsupported_value, "malformed"),
        (cyclic_value, "container cycle"),
        (excessive_depth, "maximum protocol nesting depth"),
    )
    for envelope, message in cases:
        with pytest.raises(SignatureTamperError, match=message):
            verify_scope_epoch(
                envelope,
                signer.public_key_record,
                now=NOW,
            )
    assert HostileUnsupportedValue.hook_calls == 0


def test_counterfeit_exact_enum_is_rejected_without_value_hooks() -> None:
    _, scope, _, _ = _signed_state()
    fake_purpose = str.__new__(SignaturePurpose, SignaturePurpose.SCOPE_EPOCH.value)
    object.__setattr__(fake_purpose, "_name_", "COUNTERFEIT")
    object.__setattr__(
        fake_purpose,
        "_value_",
        HostileEnumValue(SignaturePurpose.SCOPE_EPOCH.value),
    )
    block_storage = dict(object.__getattribute__(scope.signature, "__dict__"))
    forged_block = SignatureBlock.model_construct(
        **{**block_storage, "purpose": fake_purpose}
    )
    forged_envelope = SignedScopeEpoch.model_construct(
        **{
            **object.__getattribute__(scope, "__dict__"),
            "signature": forged_block,
        }
    )
    HostileEnumValue.hook_calls = 0

    with pytest.raises(ValueError, match="registered protocol enum member"):
        canonical_json_bytes({"purpose": fake_purpose})
    with pytest.raises(ValueError, match="registered protocol enum member"):
        signing_bytes(scope.payload, forged_block)
    with pytest.raises(SignatureTamperError, match="registered protocol enum member"):
        verify_scope_epoch(
            forged_envelope,
            AuthoritySigner.from_private_bytes(bytes(range(32))).public_key_record,
            now=NOW,
        )
    assert HostileEnumValue.hook_calls == 0


def test_canonical_and_signing_paths_reject_outer_or_nested_hooks() -> None:
    state = _state()
    epoch = state["epoch"]
    signer = state["authority_signer"]
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(signer, AuthoritySigner)
    scope = sign_scope_epoch(epoch, signer, signed_at=NOW)
    hooked_outer = HookedScopeEnvelope.model_validate(scope.model_dump(mode="python"))
    hooked_payload = HookedScopePayload.model_validate(epoch.model_dump(mode="python"))
    HookedScopeEnvelope.hook_calls = 0
    HookedScopePayload.hook_calls = 0
    with pytest.raises(ValueError, match="exact protocol model"):
        canonical_json_bytes(hooked_outer)
    with pytest.raises(ValueError, match="exact protocol model"):
        sign_scope_epoch(hooked_payload, signer, signed_at=NOW)
    assert HookedScopeEnvelope.hook_calls == 0
    assert HookedScopePayload.hook_calls == 0


def test_all_public_signers_reject_model_construct_scalar_subclasses() -> None:
    state = _state()
    grant = state["grant"]
    epoch = state["epoch"]
    engagement = state["engagement"]
    result = state["result"]
    authority_signer = state["authority_signer"]
    outer_signer = state["outer_signer"]
    result_signer = state["result_signer"]
    assert isinstance(grant, AuthorityGrant)
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(engagement, EngagementBundle)
    assert isinstance(result, RunResultBundle)
    assert isinstance(authority_signer, AuthoritySigner)
    assert isinstance(outer_signer, AuthoritySigner)
    assert isinstance(result_signer, AuthoritySigner)

    hostile_time = FutureBypassDatetime.from_datetime(NOW)
    hostile_id = BindingBypassStr("attacker.binding")
    poisoned_grant = AuthorityGrant.model_construct(
        **{**object.__getattribute__(grant, "__dict__"), "issued_at": hostile_time}
    )
    poisoned_epoch = ScopeEpoch.model_construct(
        **{**object.__getattribute__(epoch, "__dict__"), "grant_id": hostile_id}
    )
    poisoned_engagement = EngagementBundle.model_construct(
        **{
            **object.__getattribute__(engagement, "__dict__"),
            "created_at": hostile_time,
        }
    )
    poisoned_result = RunResultBundle.model_construct(
        **{**object.__getattribute__(result, "__dict__"), "run_id": hostile_id}
    )
    FutureBypassDatetime.comparison_calls = 0
    BindingBypassStr.hook_calls = 0

    calls = (
        lambda: sign_authority_grant(
            poisoned_grant, authority_signer, signed_at=NOW
        ),
        lambda: sign_scope_epoch(poisoned_epoch, authority_signer, signed_at=NOW),
        lambda: sign_engagement_bundle(
            poisoned_engagement, outer_signer, signed_at=NOW
        ),
        lambda: sign_run_result_bundle(
            poisoned_result, result_signer, signed_at=NOW
        ),
    )
    for call in calls:
        with pytest.raises(ValueError, match="exact"):
            call()
    assert FutureBypassDatetime.comparison_calls == 0
    assert BindingBypassStr.hook_calls == 0


def test_all_public_signers_reject_datetime_subclass_controls_without_hooks() -> None:
    state = _state()
    grant = state["grant"]
    epoch = state["epoch"]
    engagement = state["engagement"]
    result = state["result"]
    authority_signer = state["authority_signer"]
    outer_signer = state["outer_signer"]
    result_signer = state["result_signer"]
    assert isinstance(grant, AuthorityGrant)
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(engagement, EngagementBundle)
    assert isinstance(result, RunResultBundle)
    assert isinstance(authority_signer, AuthoritySigner)
    assert isinstance(outer_signer, AuthoritySigner)
    assert isinstance(result_signer, AuthoritySigner)
    hostile_time = HostileDatetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    HostileDatetime.hook_calls = 0

    calls = (
        lambda: sign_authority_grant(
            grant, authority_signer, signed_at=hostile_time
        ),
        lambda: sign_scope_epoch(epoch, authority_signer, signed_at=hostile_time),
        lambda: sign_engagement_bundle(
            engagement, outer_signer, signed_at=hostile_time
        ),
        lambda: sign_run_result_bundle(
            result, result_signer, signed_at=hostile_time
        ),
    )
    for call in calls:
        with pytest.raises(ValueError, match="exact datetime"):
            call()
    assert HostileDatetime.hook_calls == 0


def test_arbitrary_timezone_is_rejected_before_timezone_hooks() -> None:
    state = _state()
    epoch = state["epoch"]
    signer = state["authority_signer"]
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(signer, AuthoritySigner)
    hostile_timezone = HostileTimezone()
    hostile_time = datetime(2030, 1, 2, 3, 4, 5, tzinfo=hostile_timezone)
    poisoned = epoch.model_copy(update={"expires_at": hostile_time})
    with pytest.raises(ValueError, match="trusted timezone"):
        sign_scope_epoch(poisoned, signer, signed_at=NOW)
    with pytest.raises(ValueError, match="trusted timezone"):
        canonical_json_bytes({"at": hostile_time})
    assert hostile_timezone.hook_calls == 0


def test_builtin_offset_and_json_pydantic_timezone_normalize_safely() -> None:
    state = _state()
    epoch = state["epoch"]
    signer = state["authority_signer"]
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(signer, AuthoritySigner)
    korea = timezone(timedelta(hours=9))
    offset_epoch = ScopeEpoch.model_validate(
        {
            **epoch.model_dump(mode="python"),
            "issued_at": epoch.issued_at.astimezone(korea),
            "expires_at": epoch.expires_at.astimezone(korea),
        }
    )
    assert offset_epoch.issued_at.tzinfo is timezone.utc
    signed = sign_scope_epoch(offset_epoch, signer, signed_at=NOW)
    restored = SignedScopeEpoch.model_validate_json(signed.model_dump_json())
    assert restored.payload.issued_at.tzinfo is timezone.utc
    assert restored.signature.signed_at.tzinfo is timezone.utc
    assert verify_scope_epoch(restored, signer.public_key_record, now=NOW) == offset_epoch


@pytest.mark.parametrize(
    ("field", "python_value", "json_value"),
    [
        (
            "issued_at",
            datetime.min.replace(tzinfo=timezone(timedelta(hours=14))),
            "0001-01-01T00:00:00+14:00",
        ),
        (
            "expires_at",
            datetime.max.replace(tzinfo=timezone(-timedelta(hours=14))),
            "9999-12-31T23:59:59.999999-14:00",
        ),
    ],
)
def test_builtin_offset_overflow_is_a_bounded_validation_error(
    field: str,
    python_value: datetime,
    json_value: str,
) -> None:
    with pytest.raises(ValueError, match="supported UTC datetime range"):
        canonical_json_bytes({"at": python_value})

    epoch = _state()["epoch"]
    assert isinstance(epoch, ScopeEpoch)
    document = epoch.model_dump(mode="json")
    document[field] = json_value
    with pytest.raises(ValueError, match="supported UTC datetime range"):
        ScopeEpoch.model_validate_json(json.dumps(document))


def _issuer() -> GatewayEpochReceiptIssuer:
    return GatewayEpochReceiptIssuer(
        channel_key_id="gateway-channel:t13-a5",
        channel_key=bytes(range(32)),
        gateway_boot_id="gateway-boot:t13-a5",
        gateway_challenge=bytes(range(32, 64)),
    )


def test_invalid_revoked_signature_never_receives_a_gateway_receipt() -> None:
    state = _state()
    epoch = state["epoch"]
    signer = state["authority_signer"]
    attacker = state["attacker_signer"]
    assert isinstance(epoch, ScopeEpoch)
    assert isinstance(signer, AuthoritySigner)
    assert isinstance(attacker, AuthoritySigner)
    revoked = epoch.model_copy(
        update={
            "epoch": epoch.epoch + 1,
            "revoked": True,
            "revocation_reason": "forged revocation",
        }
    )
    attacker_envelope = sign_scope_epoch(revoked, attacker, signed_at=NOW)
    forged_block = attacker_envelope.signature.model_copy(
        update={"key_id": signer.key_id, "signature": "A" * 86}
    )
    forged = attacker_envelope.model_copy(update={"signature": forged_block})
    verified_at = NOW.replace(microsecond=679_000)
    signal_key = RevocationSignalKeyRecord.model_validate(
        signer.public_key_record.model_dump(mode="python")
    )
    RevocationSignalKeyRecord.hook_calls = 0
    for key in (signer.public_key_record, signal_key):
        with pytest.raises((ValueError, SignatureTamperError)):
            _issuer().issue_scope_epoch_receipt(
                forged,
                key,
                minimum_epoch=revoked.epoch,
                expected_grant_id=revoked.grant_id,
                verified_at=verified_at,
                receipt_expires_at=verified_at + timedelta(seconds=1),
                nonce=bytes(range(16)),
            )
    assert RevocationSignalKeyRecord.hook_calls == 0


@pytest.mark.parametrize(
    ("control", "value"),
    [
        ("verified_at", HostileDatetime(2030, 1, 2, tzinfo=timezone.utc)),
        ("minimum_epoch", RollbackBypassInt(1)),
        ("expected_grant_id", BindingBypassStr("grant.1")),
        ("nonce", HostileBytes(bytes(range(16)))),
    ],
)
def test_gateway_controls_precede_envelope_and_key_hooks(
    control: str, value: object
) -> None:
    _, scope, _, _ = _signed_state()
    hooked_envelope = HookedScopeEnvelope.model_validate(scope.model_dump(mode="python"))
    key = RevocationSignalKeyRecord.model_validate(
        AuthoritySigner.from_private_bytes(bytes(range(32)))
        .public_key_record.model_dump(mode="python")
    )
    HookedScopeEnvelope.hook_calls = 0
    RevocationSignalKeyRecord.hook_calls = 0
    controls: dict[str, object] = {
        "minimum_epoch": scope.payload.epoch,
        "expected_grant_id": scope.payload.grant_id,
        "verified_at": NOW.replace(microsecond=679_000),
        "receipt_expires_at": NOW.replace(microsecond=679_000)
        + timedelta(seconds=1),
        "nonce": bytes(range(16)),
    }
    controls[control] = value
    with pytest.raises(ValueError):
        _issuer().issue_scope_epoch_receipt(
            hooked_envelope,
            key,
            **controls,  # type: ignore[arg-type]
        )
    assert HookedScopeEnvelope.hook_calls == 0
    assert RevocationSignalKeyRecord.hook_calls == 0


def test_gateway_rejects_custom_timezone_controls_without_hooks() -> None:
    _, scope, _, _ = _signed_state()
    hostile_timezone = HostileTimezone()
    verified_at = datetime(2030, 1, 2, 3, 4, 5, tzinfo=hostile_timezone)
    with pytest.raises(ValueError, match="trusted timezone"):
        _issuer().issue_scope_epoch_receipt(
            scope,
            AuthoritySigner.from_private_bytes(bytes(range(32))).public_key_record,
            minimum_epoch=scope.payload.epoch,
            expected_grant_id=scope.payload.grant_id,
            verified_at=verified_at,
            receipt_expires_at=NOW.replace(microsecond=679_000)
            + timedelta(seconds=1),
            nonce=bytes(range(16)),
        )
    assert hostile_timezone.hook_calls == 0


def test_each_trusted_key_is_snapshotted_once_per_public_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, scope, engagement, result = _signed_state()
    state = _state()
    authority_signer = state["authority_signer"]
    outer_signer = state["outer_signer"]
    result_signer = state["result_signer"]
    result_payload = state["result"]
    assert isinstance(authority_signer, AuthoritySigner)
    assert isinstance(outer_signer, AuthoritySigner)
    assert isinstance(result_signer, AuthoritySigner)
    assert isinstance(result_payload, RunResultBundle)
    authority_key = authority_signer.public_key_record
    outer_key = outer_signer.public_key_record
    result_key = result_signer.public_key_record
    original = signing_module._snapshot_trusted_public_key
    calls: list[int] = []

    def counted(record: Ed25519PublicKeyRecord):  # type: ignore[no-untyped-def]
        calls.append(id(record))
        return original(record)

    monkeypatch.setattr(signing_module, "_snapshot_trusted_public_key", counted)
    cases = (
        (
            lambda: verify_authority_grant(authority, authority_key, now=NOW),
            (authority_key,),
        ),
        (
            lambda: verify_scope_epoch(scope, authority_key, now=NOW),
            (authority_key,),
        ),
        (
            lambda: verify_engagement_bundle(
                engagement,
                outer_key,
                authority_public_key=authority_key,
                now=NOW,
            ),
            (outer_key, authority_key),
        ),
        (
            lambda: verify_run_result_bundle(
                result,
                result_key,
                now=NOW,
                expected_run_id=result_payload.run_id,
                expected_run_manifest_digest=result_payload.run_manifest_digest,
                expected_authority_digest=result_payload.authority_digest,
            ),
            (result_key,),
        ),
    )
    for call, expected_records in cases:
        calls.clear()
        call()
        assert len(calls) == len(expected_records)
        for record in expected_records:
            assert calls.count(id(record)) == 1
