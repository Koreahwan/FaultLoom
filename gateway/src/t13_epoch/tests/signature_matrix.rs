use super::fixture::{EpochSpec, ReceiptCase, golden, sign, wrapped};
use super::trust::{
    ExpectedFixture, NOW_MILLIS, TrustCase, authority_key, key_id, other_key, verifier,
};
use crate::ipc::ActionClass;
use crate::scope::{
    DeterministicScopeKernel, EpochAdmissionError, EpochVerifier, IpNetwork, ScopeClock,
    ScopePolicy, TargetRule, TimeWindow,
};

struct FixedClock;

impl ScopeClock for FixedClock {
    fn now_millis(&self) -> u64 {
        NOW_MILLIS
    }
}

#[test]
fn real_ed25519_scope_epochs_verify_for_golden_and_runtime_fixtures() {
    // Given: independently generated golden bytes and a runtime-style signed epoch.
    let golden = golden();
    let artifact = sign(&EpochSpec::valid(7), &authority_key());
    let runtime = wrapped(&artifact, ReceiptCase::Valid);

    // When: each envelope crosses a verifier with the exact installed grant pin.
    let golden_result =
        verifier(TrustCase::Active, ExpectedFixture::golden()).verify(&golden, NOW_MILLIS);
    let runtime_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&runtime, NOW_MILLIS);

    // Then: both real signatures produce the correlated epoch.
    assert_eq!(golden_result.expect("golden epoch").epoch(), 7);
    assert_eq!(runtime_result.expect("runtime epoch").epoch(), 7);
}

#[test]
fn forged_86_character_signature_with_recomputed_receipt_hmac_is_rejected() {
    // Given: a canonical envelope with an 86-character forgery and a fresh valid receipt HMAC.
    let mut spec = EpochSpec::valid(7);
    spec.signature_override = Some("A".repeat(86));
    let envelope = wrapped(&sign(&spec, &authority_key()), ReceiptCase::Valid);

    // When: the forged envelope crosses the installed active key boundary.
    let result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&envelope, NOW_MILLIS);

    // Then: strict Ed25519 verification rejects it before receipt authentication can authorize it.
    assert_eq!(result, Err(EpochAdmissionError::VerificationFailed));
}

#[test]
fn revoked_and_active_unpinned_authority_keys_are_rejected() {
    // Given: one real signature evaluated under revoked and active-but-unpinned trust stores.
    let envelope = wrapped(
        &sign(&EpochSpec::valid(7), &authority_key()),
        ReceiptCase::Valid,
    );

    // When: each installed trust policy evaluates the same signature.
    let revoked =
        verifier(TrustCase::Revoked, ExpectedFixture::standard()).verify(&envelope, NOW_MILLIS);
    let unpinned = verifier(TrustCase::ActiveUnpinned, ExpectedFixture::standard())
        .verify(&envelope, NOW_MILLIS);

    // Then: revocation and grant pinning remain distinct fail-closed results.
    assert_eq!(revoked, Err(EpochAdmissionError::TrustAnchorRevoked));
    assert_eq!(unpinned, Err(EpochAdmissionError::GrantMismatch));
}

#[test]
fn unknown_candidate_and_wrong_cryptographic_key_are_rejected() {
    // Given: an absent candidate and an attacker signature mislabeled as the installed key.
    let unknown = wrapped(
        &sign(&EpochSpec::valid(7), &authority_key()),
        ReceiptCase::Valid,
    );
    let mut mislabeled = EpochSpec::valid(7);
    mislabeled.key_id_override = Some(key_id(&authority_key()));
    let wrong = wrapped(&sign(&mislabeled, &other_key()), ReceiptCase::Valid);

    // When: installed trust selection and strict verification run in order.
    let unknown_result = verifier(TrustCase::AuthorityUnknown, ExpectedFixture::standard())
        .verify(&unknown, NOW_MILLIS);
    let wrong_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&wrong, NOW_MILLIS);

    // Then: neither attacker-controlled key metadata nor a wrong signature authorizes the epoch.
    assert_eq!(unknown_result, Err(EpochAdmissionError::UnknownKey));
    assert_eq!(wrong_result, Err(EpochAdmissionError::VerificationFailed));
}

#[test]
fn wrong_purpose_and_noncanonical_envelopes_are_rejected() {
    // Given: a correctly signed wrong-purpose envelope and noncanonical bytes with valid receipts.
    let mut wrong_purpose_spec = EpochSpec::valid(7);
    wrong_purpose_spec.purpose = "authority_grant".to_owned();
    let wrong_purpose = wrapped(
        &sign(&wrong_purpose_spec, &authority_key()),
        ReceiptCase::Valid,
    );
    let mut noncanonical_artifact = sign(&EpochSpec::valid(7), &authority_key());
    noncanonical_artifact.bytes.insert(0, b' ');
    let noncanonical = wrapped(&noncanonical_artifact, ReceiptCase::Valid);

    // When: strict signed-protocol controls inspect both envelopes.
    let purpose_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&wrong_purpose, NOW_MILLIS);
    let canonical_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&noncanonical, NOW_MILLIS);

    // Then: purpose and canonical JSON are mandatory before receipt parsing.
    assert_eq!(purpose_result, Err(EpochAdmissionError::InvalidEnvelope));
    assert_eq!(canonical_result, Err(EpochAdmissionError::InvalidEnvelope));
}

#[test]
fn future_and_expired_signatures_are_rejected() {
    // Given: real signatures whose signed-at or expiry bounds exclude the verification time.
    let mut future_spec = EpochSpec::valid(7);
    future_spec.signed_at = "2030-01-02T03:09:05.680000Z".to_owned();
    let future = wrapped(&sign(&future_spec, &authority_key()), ReceiptCase::Valid);
    let mut expired_spec = EpochSpec::valid(7);
    expired_spec.issued_at = "2030-01-02T03:03:00.000000Z".to_owned();
    expired_spec.signed_at = "2030-01-02T03:03:01.000000Z".to_owned();
    expired_spec.expires_at = "2030-01-02T03:04:05.679000Z".to_owned();
    let expired = wrapped(&sign(&expired_spec, &authority_key()), ReceiptCase::Valid);

    // When: strict time controls evaluate each signed envelope.
    let future_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&future, NOW_MILLIS);
    let expired_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&expired, NOW_MILLIS);

    // Then: future and expired authority statements fail before receipt authentication.
    assert_eq!(future_result, Err(EpochAdmissionError::NotYetValid));
    assert_eq!(expired_result, Err(EpochAdmissionError::Expired));
}

#[test]
fn accepted_sequence_eight_rejects_real_signed_sequence_seven_rollback() {
    // Given: real signed epochs eight and seven under one atomic scope admission boundary.
    let eight = wrapped(
        &sign(&EpochSpec::valid(8), &authority_key()),
        ReceiptCase::Valid,
    );
    let seven = wrapped(
        &sign(&EpochSpec::valid(7), &authority_key()),
        ReceiptCase::Valid,
    );
    let kernel = DeterministicScopeKernel::new(
        policy(),
        verifier(TrustCase::Active, ExpectedFixture::standard()),
        FixedClock,
    )
    .expect("test scope policy");

    // When: sequence eight commits before sequence seven is presented.
    let accepted = kernel.admit_epoch(&eight);
    let rollback = kernel.admit_epoch(&seven);

    // Then: the lower sequence is rejected even though its Ed25519 signature is valid.
    assert_eq!(accepted.expect("sequence eight").current_epoch, 8);
    assert_eq!(rollback, Err(EpochAdmissionError::Rollback));
}

fn policy() -> ScopePolicy {
    ScopePolicy {
        grant_id: "grant.test".to_owned(),
        grant_version: 3,
        targets: vec![TargetRule {
            target_id: "target.test".to_owned(),
            host_patterns: vec!["target.test".to_owned()],
            networks: vec![
                IpNetwork::new("127.0.0.0".parse().expect("loopback network"), 8)
                    .expect("canonical loopback network"),
            ],
            ports: vec![8080],
            protocols: vec!["http".to_owned()],
            path_patterns: vec!["/probe".to_owned()],
            methods: vec!["POST".to_owned()],
            supporting_read_only: false,
        }],
        pack_ids: vec!["web".to_owned()],
        allowed_classes: vec![ActionClass::Observe],
        allowed_families: vec!["http.semantic".to_owned()],
        allowed_methods: vec!["POST".to_owned()],
        allowed_path_patterns: vec!["/probe".to_owned()],
        denied: Vec::new(),
        identities: vec!["identity.test".to_owned()],
        tenants: Vec::new(),
        execution_windows: vec![TimeWindow {
            starts_at_millis: NOW_MILLIS - 1_000,
            ends_at_millis: NOW_MILLIS + 60_000,
        }],
        state_change_families: Vec::new(),
    }
}
