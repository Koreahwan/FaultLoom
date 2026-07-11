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

The crate has no external dependencies. Installation does not grant authority,
and this foundation does not implement T16 scope evaluation, T18 lease/budget
accounting, or T19 semantic HTTP/browser execution.
