use serde_json::{Number, Value, json};

use crate::canonical_json::{CanonicalJsonError, canonical_json_bytes, parse_canonical_json};

#[test]
fn python_compatible_canonical_json_round_trips_exact_utf8() {
    // Given: sorted keys, compact separators, Unicode, and signed integers.
    let encoded = "{\"a\":[true,null,-7],\"z\":\"철회\"}".as_bytes();

    // When: the gateway parses and re-encodes the document.
    let value = parse_canonical_json(encoded, 1_024).expect("canonical Python JSON");
    let restored = canonical_json_bytes(&value, 1_024).expect("canonical bytes");

    // Then: the byte representation is unique across Python and Rust.
    assert_eq!(restored, encoded);
}

#[test]
fn whitespace_key_order_and_duplicate_aliases_are_rejected() {
    // Given: semantically similar but noncanonical JSON encodings.
    let invalid = [
        b" {\"a\":1}".as_slice(),
        b"{\"z\":1,\"a\":2}".as_slice(),
        b"{\"a\":1,\"a\":1}".as_slice(),
    ];

    // When / Then: none can alias the canonical signed bytes.
    for encoded in invalid {
        assert_eq!(
            parse_canonical_json(encoded, 1_024),
            Err(CanonicalJsonError::NonCanonical)
        );
    }
    assert_eq!(
        parse_canonical_json(b"{\"a\":-0}", 1_024),
        Err(CanonicalJsonError::InvalidNumber)
    );
}

#[test]
fn floats_and_integers_outside_signed_64_bit_are_rejected() {
    // Given: JSON numeric forms forbidden by the Python protocol profile.
    let invalid = [
        b"{\"n\":1.0}".as_slice(),
        b"{\"n\":1e3}".as_slice(),
        b"{\"n\":9223372036854775808}".as_slice(),
        b"{\"n\":-9223372036854775809}".as_slice(),
    ];

    // When / Then: the numeric boundary fails closed before signature checks.
    for encoded in invalid {
        assert!(matches!(
            parse_canonical_json(encoded, 1_024),
            Err(CanonicalJsonError::InvalidNumber | CanonicalJsonError::Malformed)
        ));
    }

    // Given: an internally constructed unsigned JSON integer beyond i64.
    let value = Value::Number(Number::from(u64::MAX));

    // When / Then: canonical serialization enforces the same boundary.
    assert_eq!(
        canonical_json_bytes(&value, 1_024),
        Err(CanonicalJsonError::InvalidNumber)
    );
}

#[test]
fn canonical_json_is_nonempty_utf8_and_bounded() {
    // Given / When / Then: malformed boundary inputs have distinct failures.
    assert_eq!(
        parse_canonical_json(b"", 16),
        Err(CanonicalJsonError::Empty)
    );
    assert_eq!(
        parse_canonical_json(&[0xff], 16),
        Err(CanonicalJsonError::InvalidUtf8)
    );
    assert_eq!(
        parse_canonical_json(b"{\"a\":1}", 6),
        Err(CanonicalJsonError::TooLarge { maximum: 6 })
    );
    assert_eq!(
        canonical_json_bytes(&json!({"payload": "too large"}), 4),
        Err(CanonicalJsonError::TooLarge { maximum: 4 })
    );
}
