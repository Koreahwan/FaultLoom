use super::{InstalledTrustError, parse_installed_trust_store};

const AUTHORITY_KEY_ID: &str =
    "ed25519:sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
const OTHER_AUTHORITY_KEY_ID: &str =
    "ed25519:sha256:dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e";
const CONTROLLER_KEY_ID: &str =
    "ed25519:sha256:39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f";
const OTHER_CONTROLLER_KEY_ID: &str =
    "ed25519:sha256:e9d34f31bb296fc48f4a768e2b8ca4651ba365df51dbe4f2660d56767d4915e8";

fn canonical_store() -> String {
    format!(
        concat!(
            "{{\"authority_keys\":[",
            "{{\"key_id\":\"{authority_key_id}\",",
            "\"public_key_base64url\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",",
            "\"status\":\"active\"}},",
            "{{\"key_id\":\"{other_authority_key_id}\",",
            "\"public_key_base64url\":\"_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU\",",
            "\"status\":\"active\"}}],",
            "\"controller_keys\":[{{\"key_id\":\"{controller_key_id}\",",
            "\"public_key_base64url\":\"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw\",",
            "\"status\":\"active\"}},",
            "{{\"key_id\":\"{other_controller_key_id}\",",
            "\"public_key_base64url\":\"3SAheomiGBAwuHHXrQ-fouq4yO1ccVYX2c0MvqXP470\",",
            "\"status\":\"active\"}}],",
            "\"generation\":7,",
            "\"grant_pins\":[{{",
            "\"authority_key_ids\":[\"{authority_key_id}\"],",
            "\"controller_key_ids\":[\"{controller_key_id}\"],",
            "\"grant_id\":\"grant-alpha\",\"minimum_version\":3}}],",
            "\"schema_version\":1}}"
        ),
        authority_key_id = AUTHORITY_KEY_ID,
        other_authority_key_id = OTHER_AUTHORITY_KEY_ID,
        controller_key_id = CONTROLLER_KEY_ID,
        other_controller_key_id = OTHER_CONTROLLER_KEY_ID,
    )
}

#[test]
fn canonical_store_exposes_only_pinned_active_roots_for_the_exact_grant_version() {
    // Given: a canonical store with distinct authority and controller roots.
    let raw = canonical_store();

    // When: the store is parsed and its exact grant pin is queried.
    let store = parse_installed_trust_store(raw.as_bytes()).expect("canonical trust store");

    // Then: generation and both role-specific roots are available through their gates.
    assert_eq!(store.generation(), 7);
    assert_eq!(
        store
            .authority_root(AUTHORITY_KEY_ID)
            .expect("active authority root")
            .key_id(),
        AUTHORITY_KEY_ID
    );
    assert_eq!(
        store.require_grant_authority("grant-alpha", 3, AUTHORITY_KEY_ID),
        Ok(())
    );
    assert_eq!(
        store
            .controller_for_grant("grant-alpha", 3, CONTROLLER_KEY_ID)
            .expect("pinned controller root")
            .key_id(),
        CONTROLLER_KEY_ID
    );
}

#[test]
fn parser_rejects_noncanonical_json_when_semantics_are_otherwise_valid() {
    // Given: valid semantics with forbidden leading whitespace.
    let raw = format!("\n{}", canonical_store());

    // When: the document crosses the trust boundary.
    let result = parse_installed_trust_store(raw.as_bytes());

    // Then: byte-level canonicality is required.
    assert!(matches!(
        result,
        Err(InstalledTrustError::NonCanonicalDocument)
    ));
}

#[test]
fn parser_rejects_duplicate_fields() {
    // Given: a duplicate generation field.
    let raw = canonical_store().replace("\"generation\":7", "\"generation\":7,\"generation\":8");

    // When: the document is parsed.
    let result = parse_installed_trust_store(raw.as_bytes());

    // Then: duplicate-field ambiguity is rejected.
    assert!(matches!(
        result,
        Err(InstalledTrustError::NonCanonicalDocument)
    ));
}

#[test]
fn parser_rejects_unknown_fields() {
    // Given: a canonically positioned but unsupported field.
    let raw = canonical_store().replace(
        "\"schema_version\":1}",
        "\"schema_version\":1,\"unexpected\":true}",
    );

    // When: the document is parsed.
    let result = parse_installed_trust_store(raw.as_bytes());

    // Then: the exact v1 schema is enforced.
    assert!(matches!(result, Err(InstalledTrustError::InvalidDocument)));
}

#[test]
fn parser_rejects_key_id_that_does_not_match_public_key_digest() {
    // Given: a syntactically valid key ID bound to the wrong public key.
    let raw = canonical_store().replace(
        AUTHORITY_KEY_ID,
        "ed25519:sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );

    // When: the key is constructed at the boundary.
    let result = parse_installed_trust_store(raw.as_bytes());

    // Then: no unbound key enters the typed store.
    assert!(matches!(result, Err(InstalledTrustError::InvalidKey)));
}

#[test]
fn authority_lookup_rejects_revoked_root() {
    // Given: a valid store whose pinned authority root is revoked.
    let raw = canonical_store().replacen("\"status\":\"active\"", "\"status\":\"revoked\"", 1);
    let store = parse_installed_trust_store(raw.as_bytes()).expect("valid revoked root record");

    // When: the root is requested for signature verification.
    let result = store.authority_root(AUTHORITY_KEY_ID);

    // Then: revoked roots never leave the store.
    assert!(matches!(
        result,
        Err(InstalledTrustError::RevokedAuthorityRoot)
    ));
}

#[test]
fn grant_lookups_reject_version_below_pin_minimum() {
    // Given: a grant pin whose minimum accepted version is three.
    let raw = canonical_store();
    let store = parse_installed_trust_store(raw.as_bytes()).expect("canonical trust store");

    // When: authority and controller lookups request version two.
    let authority = store.require_grant_authority("grant-alpha", 2, AUTHORITY_KEY_ID);
    let controller = store.controller_for_grant("grant-alpha", 2, CONTROLLER_KEY_ID);

    // Then: both role paths reject rollback.
    assert!(matches!(
        authority,
        Err(InstalledTrustError::GrantVersionBelowMinimum)
    ));
    assert!(matches!(
        controller,
        Err(InstalledTrustError::GrantVersionBelowMinimum)
    ));
}

#[test]
fn grant_lookups_reject_missing_pin() {
    // Given: a store that contains no pin for the requested grant.
    let raw = canonical_store();
    let store = parse_installed_trust_store(raw.as_bytes()).expect("canonical trust store");

    // When: either role is requested for another grant.
    let authority = store.require_grant_authority("grant-missing", 3, AUTHORITY_KEY_ID);
    let controller = store.controller_for_grant("grant-missing", 3, CONTROLLER_KEY_ID);

    // Then: neither global root set silently authorizes the grant.
    assert!(matches!(
        authority,
        Err(InstalledTrustError::MissingGrantPin)
    ));
    assert!(matches!(
        controller,
        Err(InstalledTrustError::MissingGrantPin)
    ));
}

#[test]
fn grant_authority_lookup_rejects_active_but_unpinned_root() {
    // Given: a globally active authority root omitted from this grant's pin.
    let raw = canonical_store();
    let store = parse_installed_trust_store(raw.as_bytes()).expect("canonical trust store");

    // When: it is proposed for the pinned grant.
    let result = store.require_grant_authority("grant-alpha", 3, OTHER_AUTHORITY_KEY_ID);

    // Then: global installation is not grant authorization.
    assert!(matches!(
        result,
        Err(InstalledTrustError::UnpinnedAuthorityRoot)
    ));
}

#[test]
fn controller_lookup_rejects_revoked_root() {
    // Given: a valid store whose pinned controller root is revoked.
    let raw = canonical_store().replace(
        concat!(
            "\"public_key_base64url\":",
            "\"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw\",\"status\":\"active\""
        ),
        concat!(
            "\"public_key_base64url\":",
            "\"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw\",\"status\":\"revoked\""
        ),
    );
    let store = parse_installed_trust_store(raw.as_bytes()).expect("valid revoked root record");

    // When: the controller root is requested for its pinned grant.
    let result = store.controller_for_grant("grant-alpha", 3, CONTROLLER_KEY_ID);

    // Then: a pinned but revoked controller remains unusable.
    assert!(matches!(
        result,
        Err(InstalledTrustError::RevokedControllerRoot)
    ));
}

#[test]
fn controller_lookup_rejects_active_but_unpinned_root() {
    // Given: a globally active controller root omitted from this grant's pin.
    let raw = canonical_store();
    let store = parse_installed_trust_store(raw.as_bytes()).expect("canonical trust store");

    // When: it is proposed for the pinned grant.
    let result = store.controller_for_grant("grant-alpha", 3, OTHER_CONTROLLER_KEY_ID);

    // Then: global installation is not controller authorization.
    assert!(matches!(
        result,
        Err(InstalledTrustError::UnpinnedControllerRoot)
    ));
}

#[test]
fn parser_rejects_zero_generation_zero_minimum_and_duplicate_ids() {
    // Given: three independently malformed trust stores.
    let zero_generation = canonical_store().replace("\"generation\":7", "\"generation\":0");
    let zero_minimum = canonical_store().replace("\"minimum_version\":3", "\"minimum_version\":0");
    let duplicate_key = canonical_store().replace(OTHER_AUTHORITY_KEY_ID, AUTHORITY_KEY_ID);

    // When: each document crosses the boundary.
    let generation_result = parse_installed_trust_store(zero_generation.as_bytes());
    let minimum_result = parse_installed_trust_store(zero_minimum.as_bytes());
    let duplicate_result = parse_installed_trust_store(duplicate_key.as_bytes());

    // Then: generation, version, and identity uniqueness are mandatory.
    assert!(matches!(
        generation_result,
        Err(InstalledTrustError::InvalidGeneration)
    ));
    assert!(matches!(
        minimum_result,
        Err(InstalledTrustError::InvalidGrantPin)
    ));
    assert!(matches!(
        duplicate_result,
        Err(InstalledTrustError::DuplicateKeyId)
    ));
}
