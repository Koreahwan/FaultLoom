use crate::protocol_time::ProtocolTime;
use crate::signed_protocol::{
    SignatureControls, SignaturePurpose, SignedProtocolError, TrustedEd25519Key, TrustedKeyStatus,
    untrusted_signing_key_id, verify_signed_envelope,
};

const KEY_ID: &str =
    "ed25519:sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c";
const PUBLIC_KEY: &str = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const ATTACKER_KEY_ID: &str =
    "ed25519:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUTHORITY_GOLDEN: &str = r#"{"payload":{"action_policy":{"allowed_classes":["observe","safe_probe"],"allowed_families":["http.semantic","browser.observe"],"allowed_methods":["GET","POST"],"allowed_path_patterns":["/api/*"],"denied":[{"action_families":["external_message"],"deny_id":"deny.external-message","host_pattern":null,"methods":[],"path_pattern":null,"reason":"External messages are not approved.","schema_version":"0.1.0","target_id":"target.lab"}],"schema_version":"0.1.0"},"adapter_ids":["adapter.http"],"approved_by":"operator.1","budget":{"max_concurrency":2,"max_duration_seconds":3600,"max_request_bytes":4096,"max_response_bytes":65536,"rate_per_minute":10,"schema_version":"0.1.0","total_actions":100},"callback_policy":{"maximum_ttl_seconds":300,"owned_domains":["callbacks.loopback.test"],"schema_version":"0.1.0"},"draft_digest":"sha256:cdacbdd33255082f9199ce331c3d36b744e2a3d05f8f00d4ea13ecd1ea804ff2","emergency_contact_ref":"contact.stop","execution_windows":[{"ends_at":"2030-01-02T05:04:05.678901Z","schema_version":"0.1.0","starts_at":"2030-01-02T03:04:05.678901Z"}],"expires_at":"2030-01-02T05:04:05.678901Z","grant_id":"grant.1","grant_version":3,"identities":["identity.owner"],"issued_at":"2030-01-02T03:04:05.678901Z","issued_to":"researcher.1","not_before":"2030-01-02T03:04:05.678901Z","pack_ids":["pack.web"],"provider_policy":{"allowed_model_snapshots":["frontier-2030-01-01"],"allowed_providers":["provider.test"],"arbitrary_provider_web_tools":false,"data_policy_id":"policy.no-training","schema_version":"0.1.0"},"retention_policy":{"delete_after_seconds":60,"policy_id":"retention.short","retain_until":"2030-01-02T05:04:05.678901Z","schema_version":"0.1.0"},"roles":["role.owner"],"schema_version":"0.1.0","state_change_policy":{"allowed_families":[],"canary_required":true,"cleanup_plan_required":true,"external_messages_allowed":false,"payment_or_real_asset_change_allowed":false,"schema_version":"0.1.0"},"targets":[{"cidrs":[],"hostnames":["loopback.test"],"methods":["GET","POST"],"paths":["/api"],"ports":[443],"protocols":["https"],"schema_version":"0.1.0","supporting_read_only":false,"target_id":"target.lab"}],"tenants":["tenant.alpha"]},"schema_version":"0.1.0","signature":{"algorithm":"Ed25519","expires_at":"2030-01-02T05:04:05.678901Z","key_id":"ed25519:sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c","payload_digest":"sha256:44ac704af0426d695fa90b726a1f48dbd6c798f3c9f045dc146bf947f83112b0","protocol_version":"0.1.0","purpose":"authority_grant","schema_version":"0.1.0","sequence":3,"signature":"fXLAe9j4WFl5e-L2Mad3e28lcvL6PDIkSIVcQhVkLRAjSM2M42AjJ0SDh0cyrzdA_JfMOuhd8oEqWyvLTgzlAg","signed_at":"2030-01-02T03:04:05.678901Z"}}"#;

fn trusted(status: TrustedKeyStatus) -> TrustedEd25519Key {
    TrustedEd25519Key::from_base64(KEY_ID.to_owned(), PUBLIC_KEY, status)
        .expect("Python golden public key")
}

fn at(value: &str) -> ProtocolTime {
    ProtocolTime::parse_canonical(value).expect("test timestamp")
}

fn controls(purpose: SignaturePurpose, now: &str, minimum: u64) -> SignatureControls {
    SignatureControls::new(purpose, at(now), 0, minimum).expect("verification controls")
}

fn epoch_golden() -> &'static [u8] {
    include_bytes!("../../packages/protocol/tests/fixtures/scope_epoch_signed_envelope_v0_1.json")
        .strip_suffix(b"\n")
        .expect("fixture newline")
}

fn replace_once(source: &[u8], from: &str, to: &str) -> Vec<u8> {
    std::str::from_utf8(source)
        .expect("UTF-8 fixture")
        .replacen(from, to, 1)
        .into_bytes()
}

#[test]
fn python_authority_and_epoch_goldens_verify_strictly() {
    // Given: independently Python-produced Ed25519 protocol envelopes.
    let key = trusted(TrustedKeyStatus::Active);
    let cases = [
        (
            AUTHORITY_GOLDEN.as_bytes(),
            controls(
                SignaturePurpose::AuthorityGrant,
                "2030-01-02T03:05:05.678901Z",
                3,
            ),
            3,
        ),
        (
            epoch_golden(),
            controls(
                SignaturePurpose::ScopeEpoch,
                "2030-01-02T03:05:05.678901Z",
                7,
            ),
            7,
        ),
    ];

    // When / Then: Rust verifies the exact Python bytes and exposes only proved state.
    for (encoded, verification, expected_sequence) in cases {
        let verified =
            verify_signed_envelope(encoded, &key, &verification).expect("valid Python signature");
        assert_eq!(verified.sequence(), expected_sequence);
        assert_eq!(verified.key_id(), KEY_ID);
        assert_eq!(verified.payload_bytes()[0], b'{');
    }
}

#[test]
fn payload_and_signature_tampering_are_rejected_independently() {
    // Given: one payload mutation and one canonical signature mutation.
    let payload_tamper = replace_once(
        AUTHORITY_GOLDEN.as_bytes(),
        "\"issued_to\":\"researcher.1\"",
        "\"issued_to\":\"attacker.01\"",
    );
    let signature_tamper = replace_once(
        AUTHORITY_GOLDEN.as_bytes(),
        "\"signature\":\"fXLA",
        "\"signature\":\"gXLA",
    );
    let key = trusted(TrustedKeyStatus::Active);
    let verification = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T03:05:05.678901Z",
        3,
    );

    // When / Then: digest tamper and signature forgery fail at their own boundary.
    assert!(matches!(
        verify_signed_envelope(&payload_tamper, &key, &verification),
        Err(SignedProtocolError::PayloadDigestMismatch)
    ));
    assert!(matches!(
        verify_signed_envelope(&signature_tamper, &key, &verification),
        Err(SignedProtocolError::SignatureInvalid)
    ));
}

#[test]
fn untrusted_key_id_can_only_select_a_candidate() {
    // Given: a canonical envelope naming a valid-looking attacker key ID.
    let forged = replace_once(AUTHORITY_GOLDEN.as_bytes(), KEY_ID, ATTACKER_KEY_ID);
    let installed = trusted(TrustedKeyStatus::Active);
    let verification = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T03:05:05.678901Z",
        3,
    );

    // When: the structural selector reads the attacker-controlled metadata.
    let selected = untrusted_signing_key_id(&forged).expect("structural candidate key ID");

    // Then: metadata never authorizes without the corresponding installed key and signature.
    assert_eq!(selected, ATTACKER_KEY_ID);
    assert!(matches!(
        verify_signed_envelope(&forged, &installed, &verification),
        Err(SignedProtocolError::KeyIdMismatch)
    ));
}

#[test]
fn revoked_mismatched_or_noncanonical_keys_fail_closed() {
    // Given: revoked trust state and noncanonical or mismatched key records.
    let revoked = trusted(TrustedKeyStatus::Revoked);
    let verification = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T03:05:05.678901Z",
        3,
    );

    // When / Then: revocation is enforced inside strict verification.
    assert!(matches!(
        verify_signed_envelope(AUTHORITY_GOLDEN.as_bytes(), &revoked, &verification),
        Err(SignedProtocolError::RevokedKey)
    ));
    assert!(matches!(
        TrustedEd25519Key::from_base64(
            ATTACKER_KEY_ID.to_owned(),
            PUBLIC_KEY,
            TrustedKeyStatus::Active,
        ),
        Err(SignedProtocolError::KeyIdMismatch)
    ));
    assert!(matches!(
        TrustedEd25519Key::from_base64(
            KEY_ID.to_owned(),
            &format!("{PUBLIC_KEY}="),
            TrustedKeyStatus::Active,
        ),
        Err(SignedProtocolError::InvalidBase64Url)
    ));
}

#[test]
fn purpose_sequence_time_and_canonical_boundaries_are_enforced() {
    // Given: valid bytes evaluated under wrong or stale controls.
    let key = trusted(TrustedKeyStatus::Active);
    let wrong_purpose = controls(
        SignaturePurpose::ScopeEpoch,
        "2030-01-02T03:05:05.678901Z",
        3,
    );
    let future = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T03:00:05.678901Z",
        3,
    );
    let expired = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T05:04:05.678901Z",
        3,
    );
    let rollback = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T03:05:05.678901Z",
        4,
    );
    let noncanonical = [b" ".as_slice(), AUTHORITY_GOLDEN.as_bytes()].concat();

    // When / Then: each independent trust boundary denies the envelope.
    assert!(matches!(
        verify_signed_envelope(AUTHORITY_GOLDEN.as_bytes(), &key, &wrong_purpose),
        Err(SignedProtocolError::PurposeMismatch)
    ));
    assert!(matches!(
        verify_signed_envelope(AUTHORITY_GOLDEN.as_bytes(), &key, &future),
        Err(SignedProtocolError::NotYetValid)
    ));
    assert!(matches!(
        verify_signed_envelope(AUTHORITY_GOLDEN.as_bytes(), &key, &expired),
        Err(SignedProtocolError::Expired)
    ));
    assert!(matches!(
        verify_signed_envelope(AUTHORITY_GOLDEN.as_bytes(), &key, &rollback),
        Err(SignedProtocolError::Rollback)
    ));
    assert!(matches!(
        untrusted_signing_key_id(&noncanonical),
        Err(SignedProtocolError::CanonicalJson(_))
    ));
}

#[test]
fn malformed_numeric_time_and_signature_metadata_are_rejected() {
    // Given: canonical JSON with forbidden numeric, time, and signature metadata forms.
    let float = replace_once(
        AUTHORITY_GOLDEN.as_bytes(),
        "\"total_actions\":100",
        "\"total_actions\":1.0",
    );
    let invalid_time = replace_once(
        AUTHORITY_GOLDEN.as_bytes(),
        "\"signed_at\":\"2030-01-02T03:04:05.678901Z\"",
        "\"signed_at\":\"2030-01-02T03:04:60.678901Z\"",
    );
    let padded_signature = replace_once(AUTHORITY_GOLDEN.as_bytes(), "TgzlAg\"", "TgzlAg=\"");
    let key = trusted(TrustedKeyStatus::Active);
    let verification = controls(
        SignaturePurpose::AuthorityGrant,
        "2030-01-02T03:05:05.678901Z",
        3,
    );

    // When / Then: malformed values never reach an authorization result.
    assert!(matches!(
        verify_signed_envelope(&float, &key, &verification),
        Err(SignedProtocolError::CanonicalJson(_))
    ));
    assert!(matches!(
        verify_signed_envelope(&invalid_time, &key, &verification),
        Err(SignedProtocolError::InvalidTimestamp)
    ));
    assert!(matches!(
        verify_signed_envelope(&padded_signature, &key, &verification),
        Err(SignedProtocolError::InvalidBase64Url)
    ));
}
