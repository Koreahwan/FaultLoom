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

An `EngagementBundle` embeds the complete `SignedAuthorityGrant`; verification
checks both signatures, current grant validity, and target, pack, identity, and
adapter authorization. Result verification requires the caller's expected run
ID, run-manifest digest, and authority digest instead of trusting those values
from the result itself.
