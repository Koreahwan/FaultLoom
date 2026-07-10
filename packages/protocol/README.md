# faultloom-protocol

`faultloom-protocol` contains the versioned, network-free data contracts shared
by FaultLoom Core, its safety Gateway, private operations, and private
evaluation. It also provides deterministic JSON hashing and Ed25519 helpers for
authority and cross-repository bundles.

The package never stores credentials, cookies, bearer tokens, private keys, or
request bodies. Contracts refer to such material through opaque `secret://`
references and content digests.

Rollback resistance is explicit: verifiers must persist the highest accepted
`grant_version`, `ScopeEpoch.epoch`, and bundle version in their own trusted
state and pass that value back as the corresponding `minimum_*` argument. A
signed older artifact is valid cryptographically but is rejected below that
trusted monotonic watermark.
