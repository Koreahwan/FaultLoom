# Canonical JSON profile

FaultLoom signatures use a deliberately small, language-neutral subset of
JSON. This is not a claim of full RFC 8785 conformance. Implementations must
apply the following exact rules before SHA-256 hashing or Ed25519 signing:

1. Convert a protocol model to an object that includes every field, including
   explicit `null` and default-valued fields.
2. Values may only be objects with string keys, arrays, UTF-8 strings, signed
   64-bit integers, booleans, `null`, and timezone-aware datetimes. Binary
   values, out-of-range integers, and floating-point numbers are rejected.
3. Normalize every datetime to UTC and render it as
   `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always including exactly six fractional
   digits.
4. Escape strings using the ordinary JSON escaping rules, without ASCII-only
   escaping. Encode the result as UTF-8.
5. Sort object keys lexicographically by Unicode code point. Emit no optional
   whitespace: separators are exactly `,` and `:`.

Digests are lowercase hex SHA-256 prefixed by `sha256:`. Ed25519 signatures are
unpadded URL-safe base64. The signed document includes the protocol version,
purpose, key ID, monotonic sequence, signing time, optional expiry, payload
digest, and the complete payload. The signature itself is never included in
the signed bytes.

Confidence and probability-like protocol fields use integer basis points in
the inclusive range 0–10000, avoiding cross-language floating-point rendering.
Golden vectors in `tests/fixtures` are normative for the v0.1 profile.
