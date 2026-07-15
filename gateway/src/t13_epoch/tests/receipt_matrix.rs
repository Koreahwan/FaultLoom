use super::fixture::{EpochSpec, ReceiptCase, sign, wrapped};
use super::trust::{ExpectedFixture, NOW_MILLIS, TrustCase, authority_key, verifier};
use crate::scope::{EpochAdmissionError, EpochVerifier};

#[test]
fn authentic_current_boot_receipt_is_accepted() {
    // Given: a real ScopeEpoch signature and a receipt bound to the current boot secrets.
    let envelope = wrapped(
        &sign(&EpochSpec::valid(7), &authority_key()),
        ReceiptCase::Valid,
    );

    // When: the receipt is checked after installed-key signature and grant-pin verification.
    let result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&envelope, NOW_MILLIS);

    // Then: the authenticated receipt releases the verified epoch to the scope kernel.
    assert_eq!(result.expect("authenticated epoch").epoch(), 7);
}

#[test]
fn corrupt_hmac_and_previous_boot_receipts_are_rejected() {
    // Given: one receipt with a corrupt MAC and one authenticated for a previous gateway boot.
    let artifact = sign(&EpochSpec::valid(7), &authority_key());
    let corrupt = wrapped(&artifact, ReceiptCase::CorruptMac);
    let previous_boot = wrapped(&artifact, ReceiptCase::PreviousBoot);

    // When: both receipts cross the current channel and boot binding.
    let corrupt_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&corrupt, NOW_MILLIS);
    let previous_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&previous_boot, NOW_MILLIS);

    // Then: neither receipt can authenticate the otherwise valid signed epoch.
    assert_eq!(
        corrupt_result,
        Err(EpochAdmissionError::InvalidVerificationReceipt)
    );
    assert_eq!(
        previous_result,
        Err(EpochAdmissionError::InvalidVerificationReceipt)
    );
}

#[test]
fn stale_future_and_overlong_receipt_windows_are_rejected() {
    // Given: validly MACed receipts outside each allowed freshness boundary.
    let artifact = sign(&EpochSpec::valid(7), &authority_key());
    let stale = wrapped(&artifact, ReceiptCase::Stale);
    let future = wrapped(&artifact, ReceiptCase::Future);
    let overlong = wrapped(&artifact, ReceiptCase::LongTtl);

    // When: receipt time policy evaluates all three envelopes.
    let stale_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&stale, NOW_MILLIS);
    let future_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&future, NOW_MILLIS);
    let overlong_result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&overlong, NOW_MILLIS);

    // Then: expiry, future skew, and maximum TTL all fail closed.
    for result in [stale_result, future_result, overlong_result] {
        assert_eq!(result, Err(EpochAdmissionError::InvalidVerificationReceipt));
    }
}

#[test]
fn payload_grant_must_match_the_installed_expected_grant() {
    // Given: a real signed and receipted epoch that names a different grant.
    let mut spec = EpochSpec::valid(7);
    spec.grant_id = "grant.other".to_owned();
    let envelope = wrapped(&sign(&spec, &authority_key()), ReceiptCase::Valid);

    // When: the verifier uses the installed expectation for grant.test version three.
    let result =
        verifier(TrustCase::Active, ExpectedFixture::standard()).verify(&envelope, NOW_MILLIS);

    // Then: signed payload correlation rejects the cross-grant epoch.
    assert_eq!(result, Err(EpochAdmissionError::GrantMismatch));
}
