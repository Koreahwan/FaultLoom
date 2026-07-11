# faultloom-gateway

`faultloom-gateway` is the separate-process target egress boundary for
FaultLoom. Its local control channel is a bounded, versioned binary protocol on
standard input and output. It accepts IP socket addresses rather than hostnames;
DNS, redirect, child-request, and revocation policy belong to T16.

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

The crate has no external dependencies. Installation does not grant authority,
and this foundation does not implement T16 scope evaluation, T18 lease/budget
accounting, or T19 semantic HTTP/browser execution.
