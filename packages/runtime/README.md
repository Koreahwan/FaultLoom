# FaultLoom runtime

This package provides the public `faultloom` command-line surface and the
durable research runtime. The v0.1 CLI starts fail closed: its loopback smoke
path validates a signed authority grant without opening a socket, and live
dispatch remains unavailable until the Gateway execution path is integrated.

Trusted authority keys are local public-key records. Pass one to `faultloom
run` with `--trusted-key`, or set `FAULTLOOM_TRUSTED_AUTHORITY_KEY` to its
path. Raw private keys and credentials are never accepted by this command.

Authority and trusted-key inputs must be regular, single-link files reached
without symlink or parent traversal. The CLI opens and binds both files before
reading either one, applies a one-mebibyte and bounded-JSON-depth limit, and
fails if either path or file metadata changes during capture. Loopback smoke
targets use canonical lowercase ASCII `localhost` names or canonical loopback
IP addresses; ambiguous hostname spellings are denied.

`faultloom` also provides the durable state primitives used by the FaultLoom
research runtime. Raw observations and their typed metadata are stored in an
engagement-scoped AES-GCM content-addressed store. SQLite/WAL stores only
authenticated references, append-only research events, redacted search text,
and graph projections.

Every `StateStore` requires an `anchor_root` outside the mutable state root.
The authenticated anchor records the latest `{sequence, event hash}` and an
engagement-key commitment. Each event also carries a domain-separated chain
MAC derived from the engagement key, so a lagging anchor advances only across
records that can be independently authenticated. Appends do not return until
both the SQLite commit and anchor replacement have been synced. If a crash
lands between those two steps, reopening verifies the anchored prefix and the
authenticated tail before advancing the anchor. A ledger behind its anchor
fails closed.

An authenticated anchor proves integrity, not freshness. An operator that
needs to detect restoration of both the state and anchor stores must retain an
`AnchorCheckpoint` in independently fresh trusted storage and pass it back as
`minimum_anchor`. FaultLoom does not claim rollback resistance when that
freshness condition is absent.

All cooperating processes for an engagement serialize CAS publication,
ledger commit, anchor advancement, and recovery through one private external
lock. Recovery validates the exact SQLite schema and FTS projection, verifies
every referenced ciphertext, reconciles interrupted CAS publication, and
atomically moves unreferenced objects into an encrypted quarantine.

This package does not manage engagement keys or trusted checkpoint storage.
Callers must obtain the 32-byte key from an operator-controlled vault, keep
the external anchor durable, and treat a failed append as requiring state
inspection before retry.
