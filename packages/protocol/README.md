# faultloom-protocol

`faultloom-protocol` contains the versioned, network-free data contracts shared
by FaultLoom Core, its safety Gateway, private operations, and private
evaluation. It also provides deterministic JSON hashing and Ed25519 helpers for
authority and cross-repository bundles.

Every protocol object requires an explicit `schema_version`. The catalog keeps
the 61 v0.1 payload types separate from six signed wire types while exporting
JSON Schema for all 67. Wire integers are bounded to signed 64-bit values.

The package never stores credentials, cookies, bearer tokens, private keys, or
request bodies. Contracts refer to such material through opaque `secret://`
references and content digests.

Rollback resistance is explicit: verifiers must persist the highest accepted
`grant_version`, `ScopeEpoch.epoch`, and bundle version in their own trusted
state and pass that value back as the corresponding `minimum_*` argument. A
signed older artifact is valid cryptographically but is rejected below that
trusted monotonic watermark.

Verifier controls are validated before operator dispatch. `now` is either
`None` or an exact base `datetime` whose `tzinfo` is an exact built-in
`datetime.timezone` or Pydantic-core `TzInfo`; trusted offsets are normalized
to UTC before comparison. Custom timezone objects are rejected without
invoking their hooks. `maximum_clock_skew` is an exact non-negative `timedelta`;
monotonic watermarks are exact positive `int` values; and expected binding
values are exact `str` values. Subclasses are rejected so they cannot override
truthiness, arithmetic, comparisons, or timezone behavior.

`GatewayEpochReceiptIssuer` is a host-side T13 capability, not a wire model.
It requires the same complete Ed25519 scope-verification proof with an explicit
pinned public key, expected grant, and monotonic epoch before authenticating the
exact canonical envelope for one Gateway boot. A valid signed revocation can
therefore reach the Gateway cancellation path, but an invalid revocation cannot
produce a receipt. Its 32-byte boot key must be injected out of band, rotated on
every Gateway start, and never exposed to a model, pack, adapter, or dispatch
RPC. Receipts expire within five seconds and are consumed once by the Gateway
kernel. The cross-language envelope and receipt fixtures under `tests/fixtures`
are normative for this local channel.

`ActionLease` and `DispatchReceipt` expose the durable T18 bindings without
exposing a lease proof or channel secret. Dispatch receipts also require the
Gateway-keyed authentication tag for their canonical receipt ID. They require
the grant/version, authority key, authenticated scope epoch, Gateway boot,
action/correlation, target and identity, semantic/request/resolution digests,
target-only egress plane, one-use 128-bit nonce, at-most-60-second validity, and
one-action budget.
A state-changing `ActionIntent` additionally requires a canary, pre-action
checkpoint, and cleanup-plan reference. Unknown outcomes can only proceed after
the exact authenticated dispatch receipt and a separately keyed durable
reconciliation authorization, followed by a fresh-intent retry alias.

An `EngagementBundle` embeds the complete `SignedAuthorityGrant`; verification
checks both signatures, current grant validity, and target, pack, identity, and
adapter authorization. Result verification requires the caller's expected run
ID, run-manifest digest, and authority digest instead of trusting those values
from the result itself.
