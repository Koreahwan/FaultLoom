use crate::protocol_time::{ProtocolTime, ProtocolTimeError};

#[test]
fn canonical_protocol_time_preserves_exact_microseconds() {
    // Given: a Python protocol timestamp with a non-millisecond fraction.
    let encoded = "2030-01-02T03:04:05.678901Z";

    // When: the gateway parses the canonical UTC timestamp.
    let parsed = ProtocolTime::parse_canonical(encoded).expect("canonical timestamp");

    // Then: no precision is lost and conservative millisecond bounds are available.
    assert_eq!(
        parsed,
        ProtocolTime::from_unix_micros(1_893_553_445_678_901)
    );
    assert_eq!(parsed.floor_millis(), 1_893_553_445_678);
    assert_eq!(parsed.ceil_millis(), 1_893_553_445_679);
}

#[test]
fn canonical_protocol_time_accepts_real_leap_days() {
    // Given: the first microsecond of a valid Gregorian leap day.
    let encoded = "2024-02-29T00:00:00.000001Z";

    // When: the timestamp is parsed.
    let parsed = ProtocolTime::parse_canonical(encoded).expect("leap day");

    // Then: the exact Unix coordinate is retained.
    assert_eq!(
        parsed,
        ProtocolTime::from_unix_micros(1_709_164_800_000_001)
    );
}

#[test]
fn noncanonical_or_impossible_protocol_times_are_rejected() {
    // Given: timestamps that are ambiguous, lossy, pre-epoch, or impossible.
    let invalid = [
        "2030-01-02T03:04:05Z",
        "2030-01-02T03:04:05.678901+00:00",
        "2030-01-02t03:04:05.678901Z",
        "2030-01-02T03:04:60.000000Z",
        "2023-02-29T00:00:00.000000Z",
        "1969-12-31T23:59:59.999999Z",
    ];

    // When / Then: every value fails closed at the time boundary.
    for encoded in invalid {
        assert!(matches!(
            ProtocolTime::parse_canonical(encoded),
            Err(ProtocolTimeError::InvalidFormat | ProtocolTimeError::OutOfRange)
        ));
    }
}

#[test]
fn millisecond_conversion_rejects_overflow() {
    // Given: a millisecond value that cannot be represented in microseconds.
    let value = u64::MAX;

    // When / Then: conversion fails instead of wrapping the verification clock.
    assert_eq!(
        ProtocolTime::from_unix_millis(value),
        Err(ProtocolTimeError::OutOfRange)
    );
}
