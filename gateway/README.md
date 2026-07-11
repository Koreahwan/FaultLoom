# faultloom-gateway

`faultloom-gateway` is the separate-process target egress boundary for
FaultLoom. Its local control channel is a bounded, versioned binary protocol on
standard input and output. Each request carries a resolved IP socket address plus
canonical hostname, protocol, method, path, identity, tenant, pack, action family,
and parent-flow metadata. The scope binding digest covers all of those fields.

The T15 binary is intentionally fail closed. It contains no production scope,
lease, or semantic action compiler, so every well-formed dispatch request is
denied before the target transport is reached. Later tasks must implement all
three internal verifier interfaces before a production dispatch can occur.
Tests inject fixture-only verifiers and use owned loopback listeners.
Every denied response binds `request_digest` to the complete canonical typed request
frame (or to the original raw frame when decoding fails), so changes to the target,
intent, decision, proofs, or payload cannot share a denial receipt digest.

Only `observe`, `safe_probe`, and `state_change` are representable in the typed
client API. Raw wire tags for `high_load`, `destructive`, unknown action kinds,
or unknown Gateway features are denied. A state-changing request must carry
both a canary reference and a cleanup-plan reference.

The T16 library policy is deterministic and fail closed. It applies
`explicit deny > explicit allow > ambiguity deny`, rechecks every DNS, redirect,
browser, scanner, GraphQL/batch, callback, polling, raw-schedule, and pack child,
and requires each child to name an already approved parent action in the current
epoch. Hostnames, resolved IP/CIDR, ports, protocols, paths, methods, packs,
action families/classes, identities, tenants, and execution windows must all
match explicit policy. Special-use IP space requires an explicit CIDR allow.

Epoch admission is intentionally a sealed trust boundary. The Rust kernel accepts
only the output of an injected `EpochVerifier`, binds it to the exact canonical
signed-envelope digest, verifier receipt, key ID, sequence, validity interval, and
grant ID, and rejects tamper, replay, and rollback. The production verifier remains
`UnavailableEpochVerifier`; the standalone binary therefore remains fail closed
until a non-model T13 Ed25519 verifier is wired through a sealed local channel.
Caller assertion is not treated as signature evidence.

Advancing or revoking an epoch atomically invalidates approved parent actions and
cancels registered queued actions, open connections, WebSockets, callback leases,
polling, and long scanner jobs. Expiry performs the same cancellation. The records
are deterministic integration instructions; T19 owns physical handle closure.

Build and test with the pinned toolchain and no dependency downloads:

```bash
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo build --package faultloom-gateway --release --locked --offline
```

The official Core artifact path is `python3 tools/verify_clean_checkout.py`. It
content-verifies and privately stages Cargo/rustc, builds immutable Git inputs twice,
compares the ELF byte-for-byte, independently rebuilds it during metadata verification,
and emits `faultloom-gateway-0.1.0-x86_64-unknown-linux-gnu` with a checksum, SBOM
component, and provenance subject. Direct Cargo commands remain developer checks and
do not create an official build receipt.

The crate has no external dependencies. Installation does not grant authority.
T18 lease/budget accounting and T19 semantic HTTP/browser execution remain separate
layers and cannot bypass the T16 decision.
