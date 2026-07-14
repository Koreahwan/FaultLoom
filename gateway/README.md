# faultloom-gateway

`faultloom-gateway` is the separate-process target egress boundary for
FaultLoom. Its local control channel is a bounded, versioned binary protocol on
standard input and output. Each request carries a resolved IP socket address plus
canonical hostname, protocol, method, path, identity, tenant, pack, action family,
and parent-flow metadata. The scope binding digest covers all of those fields.

The default binary remains intentionally fail closed. Its unauthenticated stdio
surface returns `IpcAuthenticationRequired` for every frame and never enters a
scope, lease, compiler, or target transport. A trusted supervisor can instead
use `run_authenticated_fail_closed_stdio` with an inherited 32-byte channel key
and a fresh, bounded boot challenge. The authenticated envelope binds the exact
request and response frames to the key ID, boot ID, challenge digest, session,
strict sequence, one-use nonce, and TTL with HMAC-SHA-256. Wrong keys, stale
boots, tamper, replay, sequence gaps, and expired sessions fail before inner
request decoding. No secret is represented by the model/plugin dispatch RPC.
The reference authenticated surface still contains no configured production
scope or semantic action compiler, so a valid envelope receives an authenticated
typed denial without target egress.
Tests inject fixture-only verifiers and use owned loopback listeners.
Every denied response binds `request_digest` to the complete canonical typed request
frame (or to the original raw frame when decoding fails), so changes to the target,
intent, decision, proofs, or payload cannot share a denial receipt digest.

Only `observe`, `safe_probe`, and `state_change` are representable in the typed
client API. Raw wire tags for `high_load`, `destructive`, unknown action kinds,
or unknown Gateway features are denied. A state-changing request must carry
a canary reference, a stable pre-action checkpoint reference, and a cleanup-plan
reference. All three are part of the semantic action and lease binding.

The T16 library policy is deterministic and fail closed. It applies
`explicit deny > explicit allow > ambiguity deny`, rechecks every DNS, redirect,
browser, scanner, GraphQL/batch, callback, polling, raw-schedule, and pack child,
and requires each child to name an already approved parent action in the current
epoch. Hostnames, resolved IP/CIDR, ports, protocols, paths, methods, packs,
action families/classes, identities, tenants, and execution windows must all
match explicit policy. Special-use IP space requires an explicit CIDR allow.
IPv4-mapped IPv6 addresses are canonicalized before CIDR and special-use
classification, so alternate address notation cannot turn loopback, private,
link-local, shared, documentation, benchmarking, multicast, or reserved space
into an implicit hostname-only allow.

Epoch admission is intentionally a sealed trust boundary. The Rust kernel accepts
only an opaque epoch produced by a verifier implementation inside the Gateway
crate. The T13 protocol process first verifies the exact canonical
`SignedScopeEpoch` bytes with `cryptography` and an explicitly pinned Ed25519
public key. It then authenticates a short-lived, one-use receipt with a fresh
32-byte Gateway boot key. The receipt binds the canonical envelope and digest,
protocol/schema/purpose, authority key and grant IDs, epoch and sequence,
issuance/expiry/revocation fields, Gateway boot ID and fresh challenge, and a
nonce. The kernel independently pins allowed authority key IDs, authenticates
the receipt, and atomically consumes its nonce while advancing the monotonic
epoch. Tamper, wrong/unknown/revoked keys, replay, rollback, stale receipts, and
receipts captured before a Gateway restart are rejected. Failed admissions do
not consume the nonce or mutate epoch state.

The boot key, challenge, and receipt issuer are host-side capabilities and are
not represented by the model/plugin dispatch RPC. External crates cannot
implement the sealed verifier trait or construct a verified epoch. The
standalone binary continues to use `UnavailableEpochVerifier`, and therefore
remains fail closed until T18/T19 integration injects fresh boot material and
wires the host-side verifier into the lease/compiler/executor path. Caller
assertion is never treated as signature evidence. Because the receipt issuer
adds public T13 protocol code, T13 must be formally reopened and independently
reverified; an earlier T13 `fully_done` receipt does not cover this delta.

Advancing or revoking an epoch atomically invalidates approved parent actions and
cancels registered queued actions, open connections, WebSockets, callback leases,
polling, and long scanner jobs. Expiry performs the same cancellation. A resource
cannot register without a cancellation sink. Gateway dispatch registration is
serialized with epoch transition, and the lease-held TCP cancellation capability
prevents a socket from opening after cancellation completes. An already registered
stream is closed with `Shutdown::Both`; any interrupted egress becomes an
authenticated `unknown_outcome` receipt and an exact reconciliation hold.

The T18 lease kernel issues Gateway-authenticated, one-use capability proofs.
Each proof binds the lease/key IDs, intent and policy-decision digests, grant ID
and version, authority key, scope epoch and authenticated epoch digest, Gateway
boot, correlation, semantic action, resolver result, target-only egress plane,
dispatch nonce, validity interval, optional retry parent, and reservation. The
semantic and request bindings include action kind, target, identity, tenant,
parent/child flow, payload digest, state-change contract, and resolved socket.
Reservation is atomic: total-action, sliding one-minute rate, concurrency,
request, response, and duration limits are checked before any transport call.
A lease consumed before a compiler failure is not restored. Grant revocation
atomically consumes queued leases, interrupts active reservations, and puts
interrupted intents on reconciliation hold.

An `unknown_outcome` or a post-dispatch reservation overrun blocks the intent.
Reconciliation requires the exact Gateway-authenticated unknown-outcome receipt
and a terminal-evidence receipt authenticated by a separately provisioned
control-plane key. Crash and revocation holds require the same separately keyed
authorization without inventing a dispatch receipt. Reconciliation consumes
stale leases only for the exact grant ID, grant version, and intent digest, and
permits retry only through a fresh-intent, append-only alias in that same grant.
The signed reconciliation authorization includes the grant ID and version, so a
same-intent receipt from another grant cannot clear a hold or authorize a retry.
The HMAC-sealed recovery checkpoint preserves grant usage, sliding-window
timestamps, revocation, issued lease IDs, dispatch nonces, retry aliases, and
typed reconciliation holds and receipts. Restoring requires the externally
anchored checkpoint digest, the same lease key, and a different fresh Gateway
boot. Receipt-bound holds cannot be downgraded to crash/revocation holds across
recovery, and version 3 persists every reconciliation key as grant ID, grant
version, and intent digest. Any lease active at the crash becomes an
unknown-outcome hold; old
proofs can never dispatch.

Dispatch receipts use one canonical field ordering, self-verify their ID, and
carry a Gateway-keyed authentication tag over that exact ID. The ID and tag are
both encoded and decoded. Receipts carry the authority/epoch/lease/boot bindings,
correlation, semantic/request/resolution/frame digests, transport plane, nonce,
TTL, retry parent, complete reservation, compiled request digest, response,
outcome, timestamps, and byte counts. Denials likewise self-bind the exact raw
request-frame digest and reason. The authenticated response envelope prevents a
caller from substituting either a receipt or a denial.

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
and the default process does not enable target dispatch or implement T19
semantic HTTP/browser execution.
