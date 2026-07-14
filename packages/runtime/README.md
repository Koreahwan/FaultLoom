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

## Durable checkpoint resume

`CheckpointController` persists a canonical `RunManifest` and complete
`ContextState` before state changes, long batches, provider failover,
compaction, stable-watermark advancement, and turn end. Checkpoint bodies and
metadata are encrypted in the engagement CAS; the authenticated event ledger
contains references only. A checkpoint carries exact goal, plan, authority,
scope-epoch, model, hypothesis, negative-result, graph-slice, action-state,
`SecretRef`, evidence-cursor, watermark, and remaining-budget state.

Use the offline commands with an externally retained `ResumeTrustPolicy`:

```text
faultloom inspect RUN_ID --state-root /absolute/state --anchor-root /absolute/anchor \
  --trust-policy /path/resume-trust.json --engagement-key-file /path/engagement.key
faultloom resume RUN_ID --state-root /absolute/state --anchor-root /absolute/anchor \
  --trust-policy /path/resume-trust.json --engagement-key-file /path/engagement.key
```

The same paths may be supplied through `FAULTLOOM_STATE_ROOT`,
`FAULTLOOM_ANCHOR_ROOT`, `FAULTLOOM_RESUME_TRUST_POLICY`, and
`FAULTLOOM_ENGAGEMENT_KEY_FILE`. The key file must be owned by the current user,
have mode `0600`, and contain exactly one lowercase 64-character hex key with
an optional final newline. Resume verifies the external anchor floor and every
trusted digest before restoring state. It performs no network access or action
dispatch. Pending or unknown-outcome actions require explicit reconciliation;
they are never automatically retried and cannot disappear from a later
checkpoint. Resolution is atomic with an `ActionReconciliation` that names the
prior state, terminal outcome, exact authority and scope epoch, and a
checkpoint-linked evidence reference. Before a clearing checkpoint can use the
record, `record_action_reconciliation(..., evidence=...)` must bind the exact
reconciliation and matching evidence bytes in a separate authenticated ledger
event. That stage is also bound to the immediate unresolved checkpoint digest,
identity, sequence, stable watermark, and authenticated ledger position. Any
intervening checkpoint expires it; resolution then requires a new reconciliation
ID and stage bound to the newer predecessor. A crash between a stage and its
clearing checkpoint leaves the action blocked; a successor-local reference,
stale stage, or unrelated observation cannot self-authenticate resolution.
`inspect` reports blocked state without dispatching it. A provider-failover
checkpoint likewise remains
non-dispatch-ready, exposes its exact `FailoverIntent`, and accepts only the
immediate successor manifest whose model is the intent's exact target.
