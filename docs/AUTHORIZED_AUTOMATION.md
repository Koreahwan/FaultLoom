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

### 4. Offline operator compilation

The personal CLI can compile one already-produced, untrusted structured model
turn without calling a provider or a target:

```text
faultloom automation compile \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --request <automation-request.json> \
  --model-turn <model-turn.json>
```

Both JSON arguments are regular-file paths. The command re-verifies the
workspace's current signed authority, exact run, target, pack, grant version,
execution window, and trusted key. The request must contain the identical
signed grant payload, must not be future-dated, and must set
`provider_network_access` to `none`. Any action proposal fails closed because
this offline command has no admitted live adapter.

On success it atomically creates a private, create-once directory under
`<workspace>/automation/` containing canonical `result.json`, canonical
`receipt.json`, and, when present, a secret-scrubbed `candidate.md`. The result
is suitable as input to a later trusted `AutomationAdmission`, but this command
does not sign that admission, perform independent verification, dispatch a
request, or submit a report. A model CLI or API adapter that produced the input
turn remains responsible for its own provider provenance; offline compilation
does not retroactively attest which model produced the file.

### 5. Provider-neutral manual model handoff

When no configured provider adapter is appropriate, export the same bounded
prompt and one restricted function contract for a model UI, CLI, or official
API chosen by the operator:

```text
faultloom automation export-handoff \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --request <automation-request.json> \
  --provider-id <grant-approved-provider-id> \
  --trusted-disclosure-key <disclosure-approver-public-key.json> \
  --out <model-handoff.json>
```

The export repeats the exact workspace, grant, run, target, pack, and request
binding checks used by `automation compile`, and requires
`provider_network_access=none`. The selected provider must be in the signed
grant and every excerpt's signed disclosure approval is verified against one or
more supplied trusted disclosure public keys at the active workspace time. It
creates one private, create-once canonical JSON file (mode `0600`) and makes no
network, provider, Gateway, target, dispatch, submission, or verification call.
The bundle is deliberately marked `unattested_manual_handoff`: export verifies
the disclosure authorization, but does not attest which model actually uses it.
It contains no credentials, cookies, or provider connection configuration.

Give the bundle only to the selected approved provider/service, save exactly its
one function-arguments object as `model-turn.json`, then run the existing
`automation compile` command. The resulting artifact remains a candidate
requiring independent verification. Approved redacted evidence may contain a
target URL or other target detail; that is precisely why disclosure is
provider-specific and signature-verified before export.

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

`execute_and_persist_admitted_tool_plan()` is the narrow controller-owned
composition for this boundary. While holding the engagement lock, it writes an
encrypted, command/result-bound reservation **before** presenting anything to
the Gateway. A matching completed dispatch is returned without another
presentation. If a restart finds only the reservation, it conservatively seals
the dispatch as `unknown_requires_reconciliation`; it never guesses whether the
earlier process reached the Gateway and never retries. A stored final record is
reused only when its signed admission and complete dispatch identity exactly
match the newly verified request.
`revoke_campaign()` is an operator-local control primitive: StateStore
possession is its trust boundary. It writes an encrypted, monotonic revocation
for one run. Revocation is sticky, survives restart, and blocks subsequent/new
Gateway presentations before their reservation. It does not interrupt an
already in-progress dispatch holding the engagement lock; Gateway lease
cancellation remains separate future work.

The Gateway remains the only target-I/O authority for the automated
controller-provisioned pipeline. Python packs, provider adapters, and this
automation bridge do not open target sockets. The separate owner-directed
personal sender below is not Gateway automation. For the controller-provisioned
POSIX handoff, see
[`GATEWAY_PROVISIONED_HANDOFF.md`](GATEWAY_PROVISIONED_HANDOFF.md).

## Verification and reporting remain separate

Independent replay/verification is a distinct gate; a model result, candidate
outbox entry, or successful Gateway receipt does not satisfy it. Only a finding
with the verifier's required replay, negative-control, and evidence bindings
can be rendered by `faultloom report` / `render_finding_report()`. The report
outbox is also local, atomic, and create-once. It produces a draft artifact for
manual delivery and has no automatic submission connector.

## Personal direct sender, optional Burp analysis, and live-mode boundary

The active Burp path is explicitly selected and loopback-only in the current
adapter. `ActiveBurpGatewayHandoff` accepts one user-selected Burp item and a
pre-approved `GatewayDispatchCommand`, then invokes only the supplied existing
Gateway `dispatch(command)` surface. It has no HTTP client, socket, launcher,
or request-construction path and rejects non-owned/non-loopback targets. See
[`ACTIVE_BURP_GATEWAY_HANDOFF.md`](ACTIVE_BURP_GATEWAY_HANDOFF.md).

The default personal Windows request path is `faultloom scope send-request`.
It admits one regular local raw HTTP/1.1 request against the signed workspace,
then makes one direct owner-local TCP/TLS attempt. It accepts only
`GET`/`HEAD`/`OPTIONS`, requires exactly `Connection: close`, applies the
smaller signed budget and fixed 65,536-byte request / 1 MiB response caps, and
writes its raw response under the workspace. It does not follow redirects, use
a proxy, retry, or make a second request. A success result uses
`faultloom.personal-http1-send.v1` and completes the reservation internally.
Its one absolute deadline includes reservation recheck, DNS, connect, TLS,
send, and receive. The strict response subset rejects every `Transfer-Encoding`
and interim `1xx` response; `HEAD`, `204`, `205`, and `304` must have no body
bytes, while non-empty responses may use matching `Content-Length` or
close-delimited EOF framing.

For a hostname-only external target, use `https` so TLS supplies the identity
check. Plaintext `http` is accepted only when the selected numeric IP is
explicitly signed as a literal hostname or covered by a signed CIDR; an
authorized CIDR must be added when neither applies. This still permits an
explicitly signed local `127.0.0.1` target.

The default result contains no response body preview. `--body-preview-chars`
accepts `0` through `3072` but is explicit opt-in: omit it (default `0`) unless
the operator has confirmed both a non-sensitive response expectation and
permission for the selected provider/model to process that response. The
supervised project skill may request `3072` only after those confirmations.
Connection/TLS failure or any post-dispatch incomplete, malformed, or
ambiguous response returns a structured no-dispatch/ambiguous result and leaves
the reservation unresolved; the operator must not retry or fabricate a
completion. Before any evidence action, the operator/classifier must delete a
sensitive response file unless engagement retention requires keeping it.

`doctor --json` reports `personal_direct_send_enabled`,
`personal_direct_send_mode`, and `personal_direct_send_network_access`
separately. Those fields do not alter the formal `network_access` value:
`gateway_only` remains the controller-provisioned POSIX claim and `none` the
Windows manual-package claim.

`scope verify-request` and `scope complete-request` remain the separate
offline admission/accounting pair for the optional exact Burp path. They bind
one local raw HTTP/1.1 request and response digest without opening a socket or
invoking Burp. Never launch, close, or restart Burp; its exact request tool is
manual analysis only and retains its separate write approval.

`faultloom evidence add-exchange --workspace <run> --trusted-key <public-key>
--reservation-id <id> --request-file <request.raw> --response-file
<response.raw>` is the separate offline archival handoff. It re-verifies the
signed workspace even after its execution window has closed, reloads the
completed SQLite reservation, and accepts only the exact request and response
files whose sizes and SHA-256 values match the recorded completion. It rejects
symlinks, unknown or incomplete reservations, and count-only completions. It
then creates immutable request/response copies plus a
`faultloom.manual-evidence.v1` record in `evidence/raw`; that evidence ID can
be passed to `faultloom finding new --evidence <id>`. It opens no network
socket, does not call Burp, make a verification claim, or infer a hypothesis.

## Supervised HTTP/1.1 triad

For the smallest useful personal campaign primitive, the CLI also provides a
strict two-phase triad. It is deliberately separate from provider reasoning,
Gateway automation, Burp, and reporting.

First, prepare a strict `faultloom.personal-http1-triad.v1` JSON spec and two
raw HTTP/1.1 request files in the same private directory. The spec contains
one `effect` and one `negative_control` request definition. Both definitions
must use the same `GET`, `HEAD`, or `OPTIONS` method and response cap, and the
raw requests must differ only in their request-target line. The effect raw
request is reused byte-for-byte for the second send as `reproduction`. Include
the exact engagement `authorization_reference` and its
`authorization_document_sha256`; these fields document the external approval
but do not replace the signed FaultLoom scope.

When `automation compile` has already produced a private result bundle, bind
one exact admitted candidate to that operator-authored template before the
run:

```bash
faultloom campaign prepare-http1-triad \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --template <triad-v1.json> \
  --result <automation-result.json> \
  --receipt <automation-result-receipt.json> \
  --candidate-id <selected-candidate-id> \
  --out <triad-v2.json>
```

The output must remain beside the template and its two raw request files. The
command re-verifies the current workspace and exact grant, result and receipt,
selected plan receipt authority, candidate intent/digest, template, and both
request digests. The candidate must be `observe` or `safe_probe` and must match
the template's target, pack, scheme, method, effect path, and exact effect
request payload digest. Model output cannot replace the operator's request
bytes or negative control. Preparation performs no provider call, target I/O,
Burp operation, verification, or submission and returns `review_required`.
The resulting v2 spec carries create-once provenance; running or finalizing it
re-reads all bound sources, and any change fails closed. A manually authored
v1 spec remains supported.

For the normal owner-supervised path, the same candidate and template inputs
can be passed to one interactive coordinator instead of invoking all three
phase commands manually:

```bash
faultloom campaign supervise-http1-triad \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --template <triad-v1.json> \
  --result <automation-result.json> \
  --receipt <automation-result-receipt.json> \
  --candidate-id <selected-candidate-id> \
  --out <triad-v2.json>
```

The coordinator prints prompts to stderr and exactly one JSON document to
stdout. It pauses for the exact campaign-bound acknowledgement
`RUN <campaign-id>`, executes the existing no-retry three-request runner, then
shows response file paths and digests without response bodies. Only the exact
`FINALIZE <campaign-id>` acknowledgement continues to the existing offline
finalizer. Exiting at either prompt is safe to resume from the durable
checkpoint. An unresolved run, a finalization that may have started, or a
start record whose dispatch is unknown is never retried automatically and
requires manual reconciliation. The coordinator adds no provider, Burp,
independent-verification, or submission capability.

The individual phase commands below remain available for inspection and
manual operation.

```bash
faultloom campaign run-http1-triad \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --spec <triad.json>
```

The command creates its start record before any target I/O, rechecks the
signed workspace, then makes exactly three sequential requests with one
concurrency slot: effect, the same effect again, and negative control. It has
no response preview, retry, redirect, proxy, provider/model call, Burp
operation, evidence archival, or submission path. A connection/TLS failure,
429, partial or ambiguous response stops as `unresolved_no_retry`; the
operator must reconcile manually and must not rerun the campaign. Private
responses are left for the operator to classify; the run result is only
`review_required`, never a vulnerability claim.

After reviewing every response and confirming that it is non-sensitive, run:

```bash
faultloom campaign finalize-http1-triad \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --campaign-id <campaign-id> \
  --confirm-reviewed-non-sensitive
```

Finalization is offline and create-once. It verifies the bound request,
response, and body digests, archives exactly the three exchanges, and applies
only the deterministic `exact_body_digest_v1` classifier. If effect and
reproduction body digests are equal while the negative-control body digest is
different, it creates an evidence-bound `draft_unverified` finding. Any other
digest relation creates a durable `negative_campaign` and no finding. This is
not independent verification and does not prove exploitability or a
vulnerability; independent replay and the normal report gate remain separate.

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
