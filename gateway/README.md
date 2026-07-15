# faultloom-gateway

`faultloom-gateway` is the separate-process target egress boundary for
FaultLoom. Its local control channel is a bounded, versioned binary protocol on
standard input and output. Each request carries a resolved IP socket address plus
canonical hostname, protocol, method, path, identity, tenant, pack, action family,
and parent-flow metadata. The scope binding digest covers all of those fields.

The default binary remains intentionally fail closed. Its unauthenticated stdio
surface returns `IpcAuthenticationRequired` for every frame and never enters a
scope, lease, compiler, or target transport. The installed executable exposes a
separate production mode only as
`--supervised-stdio --bootstrap-fd 3 --journal-write-fd 4 --journal-read-fd 5`.
File descriptor 3 must be an inherited, private, bounded regular file containing
the canonical typed bootstrap. Descriptors 4 and 5 must be private inherited
FIFOs connected to the host-owned durable-journal sidecar. No path, URL,
hostname, socket, key, journal location, or epoch receipt is accepted on the
command line or through environment variables.

The sole public library entry that can assemble this privileged installed mode
is the argument-free `run_installed_cli()` bridge. It reads the process arguments
and inherited descriptors internally. Bootstrap types and codecs, inherited
bootstrap loading, assembly, and the supervised runner remain private to the
crate, so an external crate cannot use them to inject an alternate authority
surface.

The bootstrap pins one grant, exact target ID/hostname/IP/port/protocol,
pack/family/identity/tenant, methods, paths, action classes, execution window,
budget, channel trust, T13 receipt trust, lease key, compiler key, and boot
identity. The model/plugin-facing supervisor dispatch names only the pinned
target ID and semantic method/path/payload; it cannot select a network address.
The production assembly uses the real `DeterministicScopeKernel`,
`T13ReceiptEpochVerifier`, `LeaseAuthority`, keyed semantic HTTP compiler, and
TCP target transport. Installation alone still grants no authority because the
mode cannot start without a valid inherited bootstrap and cannot dispatch
before a fresh authenticated epoch is admitted.

The authenticated envelope binds the exact request and response frames to the
key ID, boot ID, challenge digest, session, strict sequence, one-use nonce, and
TTL with HMAC-SHA-256. The supervised runtime derives and pins the one accepted
session as `supervisor:channel:v1:<challenge-id-hex>` before replay state or
dispatch is available; callers cannot substitute an arbitrary session. Wrong
keys, sessions, stale boots, tamper, replay, sequence gaps, and expired sessions
close the channel before command decoding. Epoch admission, target-ID-only
dispatch, actual-clock expiry reconciliation, pending-response recovery, and
exact response acknowledgement are the only inner command families. Dispatch
runs on a bounded worker set so epoch advance, revocation, and expiry controls
can interrupt an active transfer. Tests use only owned loopback listeners.
Current incompatible wire revisions are Gateway IPC v4, authenticated channel
v1, inherited bootstrap v3, supervisor command/response v4, authenticated
journal v3, and lease recovery checkpoint v6; other versions fail closed during
decoding.

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
implement the sealed verifier trait or construct a verified epoch. The default
binary path still uses no verifier at all; only the explicit inherited-bootstrap
mode constructs the pinned T13 verifier and production dispatch path. Caller
assertion is never treated as signature evidence.

Advancing or revoking an epoch atomically invalidates approved parent actions and
cancels registered queued actions, open connections, WebSockets, callback leases,
polling, and long scanner jobs. Expiry performs the same cancellation. A resource
cannot register without a cancellation sink. Gateway dispatch registration is
serialized with epoch transition, and the lease-held TCP cancellation capability
prevents a socket from opening after cancellation completes. An already registered
stream is closed with `Shutdown::Both`; any interrupted egress becomes an
authenticated `unknown_outcome` receipt and an exact reconciliation hold.
Generic TCP cannot prove how many kernel-buffered bytes the peer application
observed, so active cancellation is explicitly non-acknowledged at the target
boundary. The control path waits for local transport I/O quiescence before it
returns and never represents that unknown peer outcome as a stable cancellation.

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

After reserving a durable response slot and validating the canonical dispatch,
the supervisor performs a read-only lookup of the exact grant/version/intent
reconciliation key. A paired hold/effect blocks the request before it can acquire
a worker permit, enter scope evaluation, request a compiler proof, issue or
consume a lease, or contact the target. Failed preflight does not mutate the
hold, proof, nonce, or grant budget.

Production dispatch also requires a durable pre-egress barrier. After scope,
lease, and compiler bindings agree, but before target transport can open a
socket, the Gateway sends the external journal an authenticated snapshot that
contains the lease checkpoint and exact prepared-dispatch bindings, including
the request-frame, intent, effect, and compiled-request digests. It
continues only after a sequence-, session-, stable-binding-, previous-anchor-,
and snapshot-bound journal acknowledgement. Missing, timed-out, malformed, or
anchor-mismatched journal replies deny dispatch without target egress.

An `unknown_outcome` or a post-dispatch reservation overrun blocks the intent.
The effect digest identifies the concrete target effect as the canonical action
kind, egress plane, resolution digest, and exact compiled-request digest; it is
carried by the lease, prepared-dispatch record, dispatch receipt, checkpoint,
and reconciliation evidence. This prevents a same-intent record for a different
wire effect from clearing or relabelling a hold.
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
recovery, and recovery checkpoint v6 persists every reconciliation key as grant
ID, grant version, and intent digest together with its effect digest. The
bootstrap supplies the expected journal anchor; the authenticated sidecar must
return exactly that anchor and its snapshot before the Gateway restores the
checkpoint. The last externally committed anchor and its bound snapshot remain
the restart authority; a stale or mismatched anchor fails closed without journal
mutation or target egress. Any lease active at the crash becomes an
unknown-outcome hold, grant budgets and replay sets survive the restart, and old
proofs can never dispatch.

Before sealing or writing any normal supervisor reply, the Gateway commits the
exact encoded inner response to the journal outbox. While an outbox item is
pending, normal commands are rejected: the controller may only recover the same
inner response by its original request-envelope ID or acknowledge it with both
that ID and the exact response digest. Recovery reseals the stored response and
does not contact the target. Acknowledgement atomically replaces the pending
response with a non-evicting tombstone bound to those two IDs. Exact replay of
that acknowledgement succeeds without another journal commit; a digest mismatch
fails closed. `MAX_DURABLE_RESPONSE_SLOTS` is a lifetime quota of 64 across
prepared dispatch responses, pending responses, acknowledged tombstones, and
transient in-memory reservations. Slots and tombstones are never evicted or
reused, so no work begins if a fresh response would exceed that quota.

A journal persistence failure or response sealing/output failure is a terminal
fail-stop boundary. The process does not attempt a later cleanup, checkpoint, or
acknowledgement mutation after that failure. A replacement process must recover
from the last anchor and snapshot that the external journal actually committed,
rather than assuming an unacknowledged local transition completed.

Dispatch receipts use one canonical field ordering, self-verify their ID, and
carry a Gateway-keyed authentication tag over that exact ID. The ID and tag are
both encoded and decoded. Receipts carry the authority/epoch/lease/boot bindings,
correlation, semantic/request/resolution/frame digests, transport plane, nonce,
TTL, retry parent, complete reservation, action kind, effect and compiled-request
digests, response, outcome, timestamps, and byte counts. The transport enforces
a monotonic deadline bounded by the scope epoch, lease expiry, and reserved
duration, and caps retained response bytes at the reserved maximum and Gateway
hard ceiling. Hitting either bound after target egress may have occurred is not
represented as a completed effect; it becomes `unknown_outcome` and requires
reconciliation. A deadline reached before any egress remains a stable failure.
Denials likewise self-bind the exact raw request-frame digest and reason. The
authenticated response envelope prevents a caller from substituting either a
receipt or a denial.

These guarantees do not assert exactly-once external effects. A peer may observe
bytes before a crash, timeout, cancellation, or lost response; such cases remain
`unknown_outcome`, block automatic retry, and require explicit reconciliation.
The journal provides durable admission/accounting and recoverable response
evidence, not transactional atomicity with the target application.

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
the default process never dispatches, and the explicit supervised mode supports
only the pinned semantic HTTP executor. Browser and raw transports remain
outside this surface.
