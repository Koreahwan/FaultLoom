# Authorized automation path

FaultLoom's automation path is an authorization-first, candidate-producing
workflow for owned or explicitly authorized assessments. It is split into
provider reasoning, deterministic admission, optional Gateway execution,
independent verification, and reporting. A model can suggest a finding or a
safe probe; it cannot grant itself authority, widen scope, submit a report, or
open a target socket.

## End-to-end boundary

```text
signed redacted evidence approval
        -> allowed model-provider reasoning
        -> pure coordinator admission
        -> encrypted turn / candidate outbox
        -> trusted issuer signs the exact admitted result
        -> (optional) one exact signed ToolPlan through the Gateway
        -> independent replay and verification
        -> verified report outbox (manual delivery)
```

The provider boundary is model-agnostic. An adapter may use an approved
OpenAI-compatible provider or another provider implementation, provided it
produces the pinned, signed receipt and satisfies the authority grant's
provider, model-snapshot, budget, and data-policy constraints. See
[`OPENAI_COMPATIBLE_PROVIDERS.md`](OPENAI_COMPATIBLE_PROVIDERS.md) for the
compatible-provider contract and presets.

### 1. Evidence disclosure is signed before provider access

`ObservationExcerpt` carries a `SignedModelDisclosureApproval`. The approval
binds the run, evidence reference, source CAS digest, redaction digest, exact
excerpt digest/media type, data policy, allowed provider IDs, and a short
validity window. `sign_model_disclosure_approval()` is the operator-side
signing helper; `verify_model_disclosure_approval()` verifies the envelope
against a caller-supplied trusted public-key registry. A missing, expired,
wrong-key, wrong-provider, wrong-policy, or mismatched-digest approval fails
before prompt publication or a provider request.

The provider therefore receives only the approved redacted excerpt. This is a
disclosure authorization, not a claim that the original CAS object is safe to
send. Raw evidence remains outside the model-provider input path until it has
been separately redacted and approved.

### 2. Reasoning is one bounded provider turn

`run_provider_automation_turn()` binds an `AutomationRequest` to a configured
`ProviderCallIntent`, publishes a canonical one-shot prompt through
`OneShotReasoningPromptResolver`, and accepts exactly the admitted model-turn
tool contract. The pinned provider receipt is checked for authority, provider,
snapshot, data policy, prompt/context/schema digests, and the trusted proxy
attestation. The resolver entry is tombstoned after the call, including on
failure, so a provider response cannot be replayed into another turn.
Before prompt publication it also admits the request context, evaluates the
grant, execution window, and disclosure expiry against the supplied trusted
runtime clock, and rejects future-dated or expired requests without provider
I/O.

`AuthorizedAutomationCoordinator.run()` and `parse_model_turn()` are pure
compilation/admission functions. They validate the model's hypotheses,
negative conclusions, action proposals, safe PoC proposals, and finding draft
against the supplied authority grant and scope. The result is explicitly
`candidate_only_requires_independent_verification`; it is not a verified
finding.

### 3. Durable candidate artifacts are local and create-once

`persist_automation_turn()` stores one encrypted `automation.turn.v1`
aggregate in the engagement `StateStore`; the ledger keeps authenticated
references rather than plaintext evidence. `write_candidate_outbox()` creates
one atomically published, secret-scrubbed `candidate.md` plus receipt under a
manual-review outbox. Both operations are idempotent/create-once and perform
no network access or submission.

The candidate outbox records `automatic_submission=false`,
`independent_verification=false`, and `target_dispatch=false`. A candidate
draft must go through the independent verifier before it can become a report.

## Optional authorized target dispatch

Dispatch is a separate, explicit operator/controller step. It does not happen
inside provider reasoning or the coordinator. A trusted controller first wraps
the exact `AuthorizedAutomationResult` in a short-lived
`SignedAutomationAdmission` with `sign_automation_admission()`.
`execute_admitted_tool_plan()` verifies that signature against a caller-owned
trust registry and trusted runtime clock before accepting the selected
`ToolPlanItem` and an already-issued `GatewayDispatchCommand`. It then requires
matching intent/payload, authority grant ID/version, decision/lease, and
`TARGET_GATEWAY` egress. Only `observe` and `safe_probe` action classes are
accepted. An unsigned, expired, tampered, or untrusted admission performs no
Gateway call. The function presents an admitted command to the existing
`SemanticHttpExecutor` exactly once, never retries an uncertain presentation,
and records `denied` or
`unknown_requires_reconciliation` when the Gateway does not provide a final
outcome.

`persist_automation_dispatch()` stores the dispatch aggregate encrypted and
idempotently. Its dispatch evidence is deliberately **raw/unredacted** and has
no model-disclosure approval. It must not be sent to a provider or used in a
new reasoning turn until a separate redaction operation produces a new digest
and a new signed `ModelDisclosureApproval`. The dispatch record always states
`automatic_submission_performed=false` and
`independent_verification_performed=false`.

The Gateway remains the only target-I/O authority. Python packs, provider
adapters, and this automation bridge do not open target sockets. For the
controller-provisioned POSIX handoff, see
[`GATEWAY_PROVISIONED_HANDOFF.md`](GATEWAY_PROVISIONED_HANDOFF.md).

## Verification and reporting remain separate

Independent replay/verification is a distinct gate; a model result, candidate
outbox entry, or successful Gateway receipt does not satisfy it. Only a finding
with the verifier's required replay, negative-control, and evidence bindings
can be rendered by `faultloom report` / `render_finding_report()`. The report
outbox is also local, atomic, and create-once. It produces a draft artifact for
manual delivery and has no automatic submission connector.

## Burp and live-mode boundary

The active Burp path is explicitly selected and loopback-only in the current
adapter. `ActiveBurpGatewayHandoff` accepts one user-selected Burp item and a
pre-approved `GatewayDispatchCommand`, then invokes only the supplied existing
Gateway `dispatch(command)` surface. It has no HTTP client, socket, launcher,
or request-construction path and rejects non-owned/non-loopback targets. See
[`ACTIVE_BURP_GATEWAY_HANDOFF.md`](ACTIVE_BURP_GATEWAY_HANDOFF.md).

The normal runtime is fail-closed and live mode is off by default. A POSIX
`run --live` process is supported only when an external controller provisions
the signed Gateway bootstrap, authenticated journal descriptors, channel
configuration, and an already-approved command. The personal Windows
executable remains manual-only; installation does not create authority or
enable automatic target traffic.

## What this does not claim

- It is not an automatic zero-day discovery or automatic exploitation promise.
- It does not submit HackerOne/Bugcrowd/client reports or contact external
  targets by itself.
- It is not a turnkey commercial platform, a release approval, or proof that
  the formal T04/T40/v0.1 milestone is complete.
- A provider subscription, browser cookie, or arbitrary model endpoint is not
  accepted as authority. A provider must enter through a validated adapter,
  pinned policy/metadata, and the signed receipt path.
