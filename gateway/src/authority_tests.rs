use super::test_support::{
    EXPIRES_MILLIS, NOT_BEFORE_MILLIS, authority_key, grant_payload, signed_grant, trust_store,
};
use super::{AuthorityError, AuthorityVerifier};

const SKEW_MILLIS: u64 = 300_000;

#[test]
fn verifier_rejects_an_attacker_selected_signing_key() {
    // Given: an envelope signed by a key absent from installed trust.
    let installed = authority_key(7);
    let attacker = authority_key(9);
    let trust = trust_store(&[&installed], &installed, 3);
    let raw = signed_grant(&grant_payload(), &attacker);

    // When: the authority boundary verifies the envelope.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: caller-provided signing material cannot bootstrap authority.
    assert!(matches!(result, Err(AuthorityError::UntrustedSigningKey)));
}

#[test]
fn verifier_rejects_an_active_root_not_pinned_to_the_grant() {
    // Given: an installed root that is not pinned to grant-alpha.
    let pinned = authority_key(7);
    let unpinned = authority_key(9);
    let trust = trust_store(&[&pinned, &unpinned], &pinned, 3);
    let raw = signed_grant(&grant_payload(), &unpinned);

    // When: its valid signature reaches the grant-specific gate.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: global installation alone grants no authority.
    assert!(matches!(result, Err(AuthorityError::GrantNotPinned)));
}

#[test]
fn verifier_rejects_a_signed_grant_below_the_pinned_minimum_version() {
    // Given: a valid version-two grant and a version-three pin.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let mut payload = grant_payload();
    payload["grant_version"] = 2.into();
    let raw = signed_grant(&payload, &signer);

    // When: the signed rollback crosses the authority boundary.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: the installed minimum version is authoritative.
    assert!(matches!(result, Err(AuthorityError::GrantVersionRollback)));
}

#[test]
fn verifier_accepts_the_exact_not_before_boundary() {
    // Given: a correctly signed and pinned grant.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let raw = signed_grant(&grant_payload(), &signer);

    // When: verification occurs exactly at not_before.
    let verified = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: the inclusive lower validity boundary is active.
    assert!(verified.is_ok());
}

#[test]
fn verifier_rejects_the_exact_expiry_boundary() {
    // Given: a correctly signed and pinned grant.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let raw = signed_grant(&grant_payload(), &signer);

    // When: verification occurs exactly at expires_at.
    let result = AuthorityVerifier::verify(&raw, &trust, EXPIRES_MILLIS, SKEW_MILLIS);

    // Then: the exclusive upper validity boundary has expired.
    assert!(matches!(result, Err(AuthorityError::Expired)));
}

#[test]
fn verifier_rejects_unsupported_action_classes_even_when_root_signed() {
    // Given: a root-signed grant that tries to enable high_load.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let mut payload = grant_payload();
    payload["action_policy"]["allowed_classes"] = serde_json::json!(["observe", "high_load"]);
    let raw = signed_grant(&payload, &signer);

    // When: the exact protocol model is parsed after signature verification.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: unsupported v0.1 behavior remains impossible to configure.
    assert!(matches!(
        result,
        Err(AuthorityError::UnsupportedActionClass)
    ));
}

#[test]
fn verifier_rejects_a_noncanonical_cidr_instead_of_widening_it() {
    // Given: a signed CIDR whose host bits would be masked into a wider network.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let mut payload = grant_payload();
    payload["targets"][0]["cidrs"] = serde_json::json!(["127.0.0.1/8"]);
    let raw = signed_grant(&payload, &signer);

    // When: the signed grant crosses the authority boundary.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: normalization cannot silently authorize the containing /8.
    assert!(matches!(result, Err(AuthorityError::InvalidProtocol)));
}

#[test]
fn verifier_rejects_delete_schedules_without_runtime_enforcement() {
    // Given: a root-signed grant requesting deferred deletion that the runtime cannot enforce.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let mut payload = grant_payload();
    payload["retention_policy"]["delete_after_seconds"] = 60.into();
    let raw = signed_grant(&payload, &signer);

    // When: the unenforceable retention policy crosses the authority boundary.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: the field cannot be silently discarded from normalized runtime policy.
    assert!(matches!(result, Err(AuthorityError::InvalidProtocol)));
}

#[test]
fn verifier_rejects_external_messages_without_runtime_enforcement() {
    // Given: a root-signed grant enabling external messages that the runtime cannot constrain.
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let mut payload = grant_payload();
    payload["state_change_policy"]["external_messages_allowed"] = true.into();
    let raw = signed_grant(&payload, &signer);

    // When: the unenforceable messaging policy crosses the authority boundary.
    let result = AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, SKEW_MILLIS);

    // Then: the field cannot be silently discarded from normalized runtime policy.
    assert!(matches!(result, Err(AuthorityError::InvalidProtocol)));
}
