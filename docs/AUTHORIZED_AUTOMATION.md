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
        -> independent replay of the bounded observation
        -> independently reproduced observation -> manual-review report draft
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

After `evidence add-exchange` has archived one completed authorized HTTP
exchange, the CLI can create the previously manual `AutomationRequest` without
opening a socket:

```text
faultloom automation prepare-http1-request \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --evidence-id <archived-exchange-evidence-id> \
  --excerpt-file <operator-redacted-non-sensitive.txt> \
  --provider-id <grant-approved-provider-id> \
  --disclosure-private-key <operator-disclosure-seed> \
  --hostname <exact-host> --port <exact-port> --scheme <http-or-https> \
  --method <GET-or-HEAD-or-OPTIONS> --path <exact-request-target> \
  --out <automation-request.json> \
  --confirm-redacted-non-sensitive
```

The command strictly reloads the evidence record, both archived byte files,
and the completed accounting reservation. It recomputes the original endpoint
fingerprint and current signed target/policy/deny checks, then signs the whole
endpoint-and-digest-bound redacted excerpt for only the selected provider. The
request permits one safe PoC step and zero generic adapter actions. It performs
no provider, target, Burp, verification, or submission call.

When no configured provider adapter is appropriate, export the same bounded
prompt and one restricted function contract for a model UI, CLI, or official
API chosen by the operator:

```text
faultloom automation export-handoff \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --request <automation-request.json> \
  --provider-id <grant-approved-provider-id> \
  --model-snapshot <grant-approved-exact-snapshot> \
  --trusted-disclosure-key <disclosure-approver-public-key.json> \
  --out <model-handoff.json>
```

The export repeats the exact workspace, grant, run, target, pack, and request
binding checks used by `automation compile`, and requires
`provider_network_access=none`. The selected provider and exact model snapshot
must be in the signed grant, and every excerpt's signed disclosure approval is verified against one or
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

Compiled PoC prose (expected effect, negative control, prerequisites, and
finding wording) remains untrusted explanatory material. It never replaces the
operator-authored, digest-bound effect/control request bytes or finding metadata
that govern the supervised triad.

### 6. Archived-exchange model HTTP/1 PoC supervisor

For the shortest supervised path from one completed archived exchange to a
bounded PoC comparison, use:

```text
faultloom campaign supervise-model-http1-poc \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --request <archived-exchange-automation-request.json> \
  --model-turn <external-model-turn.json> \
  --evidence-id <archived-exchange-evidence-id> \
  --negative-control-path <request-target-only-control> \
  --metadata <strict-operator-metadata.json> \
  --out <private-model-http1-poc-outbox>
```

`--out` must name exactly one safe immediate child directory of the verified
workspace (for example, `<workspace>/model-http1-poc`). The workspace root,
nested paths, and paths outside the workspace fail before any socket is opened.

The request must be the exact `AutomationRequest` derived from the archived
exchange, and the model turn is an untrusted external file. Metadata is a
strict operator-authored document containing the campaign, external
authorization reference and document digest, exact endpoint, timeout/response
limits, and finding metadata. Compilation is deterministic and offline: it
accepts zero generic actions and exactly one safe-PoC step, but never lets the
model author raw requests or finding prose. The effect file is copied from the
archived exchange byte-for-byte; the negative-control file is derived by
changing only its HTTP request-target line. Any mismatch fails closed before
the campaign start record or a socket.

The command creates a private, create-once, source-keyed bundle containing the
compiled result/receipt, exact effect and control files, triad spec, and
provenance. The provenance labels the external authorization reference
`operator_asserted_unverified`; the signed FaultLoom grant digest and run ID
are independently verified and bound. It then delegates to the normal triad
supervisor. Type exactly `RUN <campaign-id>` before dispatch and exactly
`FINALIZE <campaign-id>` only after reviewing the three private responses as
non-sensitive. The runner sends exactly three sequential requests—effect,
the same effect again as reproduction, and the derived control—with no retry.
Durable checkpoints resume without re-sending completed work; unresolved or
start-only state requires manual reconciliation. This path makes no provider,
Gateway, Burp, or submission call. When finalization returns
`finalStatus=draft_unverified`, the supervisor creates or verifies the
campaign-derived source handoff as a private direct child of the verified
workspace. Its content-addressed safe filename is
`campaign-<handoff-sha256>.verification-handoff.json`; consume the trust JSON's
`handoff` and `handoffSha256` fields rather than constructing a path. Its single
JSON result includes that handoff path, `handoffSha256`, and a `nextAction` naming the separately
authorized verifier workflow. That next action does not grant reviewer
authority: the verifier must use a separate workspace, actor, signing key, and
active grant, with its own exact `RUN <campaign-id>` and
`FINALIZE <campaign-id>` checkpoints. A pending, `review_required`, negative, or
unresolved result creates no handoff. The handoff remains
`verificationStatus=pending`; independent verification and the local `draft_manual_review` report
workflow are separate, and this path is not verification or proof of a
vulnerability.

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
one exact compiled candidate to that operator-authored template before the
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
selected-plan receipt authority when applicable, candidate intent/digest,
template, and both request digests. The candidate may be an admitted plan or
the single compiled safe-PoC recipe step. Both paths must be exactly
`safe_probe` + `http.semantic` and must match
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

### Read-only verification handoff

Only a finalized `draft_unverified` v2 campaign with its exact automation
binding may be handed to an independent verifier. The model supervisor above
creates the source-side handoff automatically. For a campaign run through the
phase commands directly, export the same manifest explicitly:

```bash
faultloom campaign export-verification-handoff \
  --workspace <signed-manual-workspace> \
  --trusted-key <public-key-outside-workspace> \
  --campaign-id <campaign-id> \
  --out <workspace-local-handoff.json>
```

`--out` must be a direct child of the workspace; nested output paths are
rejected. The output path and every referenced campaign, automation, finding, and
evidence file must be regular non-symlink files beneath the workspace. The
command revalidates the completed finalization chain, the exact v2 binding,
and the finalized finding's title, severity, summary, impact, remediation,
identity, status, and evidence IDs against the campaign start record. It then
creates one private canonical manifest containing only workspace-relative
file references, byte sizes, and SHA-256 values. It contains no raw exchange
bodies, credentials, signing keys, report, verdict, or verified finding.

The manifest requires a fresh verifier identity/reset, a positive replay, a
negative control, new verifier evidence, and no reuse of the source evidence.
It is marked `verification_handoff_ready` with verification still `pending`.
Export makes no socket, provider, target, verifier, report, outbox, or
submission call. Repeating the exact export revalidates sources and returns
the existing manifest digest without rewriting it; changed sources or any
different pre-existing output fail closed.

### Independent HTTP/1 verification bridge

Create a second manual workspace from a separately signed verifier grant, with
a different actor and signing key but the exact same target. The source may be
historical; the verifier grant and execution window must be active. Then prepare
an explicit case without opening a socket:

```bash
faultloom campaign prepare-verification-http1 \
  --source-workspace <source-workspace> --source-trusted-key <source-key> \
  --handoff <source-workspace>/verification-handoff.json \
  --verifier-workspace <verifier-workspace> --verifier-trusted-key <verifier-key> \
  --campaign-id <campaign-id> --finding-class http_response_differential \
  --claim <operator-claim> --prerequisite <operator-prerequisite> \
  --out <verifier-workspace>/verification-triad.json
```

The first slice admits only the `http_response_differential` observation class
and bodyless `GET` or `OPTIONS` requests with exactly
`Host` and `Connection: close`. `HEAD`, authorization or other headers, request
bodies, same/nested workspaces, same actors or keys, different targets, and an
expired verifier grant are rejected. The operator's `--claim` is retained in
the private case only as `operator_asserted_unverified`; it is not the claim
signed by the replay verdict. The generated case and v1 triad are private,
create-once files. Run that triad with the existing
`campaign run-http1-triad`, review the three fresh responses, and finalize it
with the existing `campaign finalize-http1-triad`; there is no second sender.

Compile the finalized transcript offline:

```bash
faultloom campaign compile-verification-http1 \
  --source-workspace <source-workspace> --source-trusted-key <source-key> \
  --handoff <source-workspace>/verification-handoff.json \
  --verifier-workspace <verifier-workspace> --verifier-trusted-key <verifier-key> \
  --campaign-id <campaign-id> \
  --case <verifier-workspace>/<campaign-id>.verification-case.json \
  --private-key <0600-verifier-key-outside-both-workspaces> \
  --result-out <verifier-workspace>/verified-result.json \
  --receipt-out <verifier-workspace>/verification-compile-receipt.json
```

Compilation makes no request. It requires the verifier effect and reproduction
digests to equal the source effect digest, the verifier control to equal the
source control, and effect to differ from control. It emits a signed
verifier-run result, a new verifier-run imported-handoff evidence reference,
and exact arguments for the existing `faultloom verify` and `faultloom report`
gates. The signed claim is fixed to the exact response-body differential, while
the public outcome is only `observation_reproduced`; `semanticVerdict` and
`taxonomyVerdict` remain `not_evaluated`. CVE, one-day, patch-variant, and
zero-day classifications are rejected by this bridge. A report remains a local
`draft_manual_review`; neither command submits it. The compile receipt records
the exact stdout-rendering report arguments. An operator who separately wants
the generic report command's optional outbox must supply and validate an
explicit `--out-dir`; the supervisor instead publishes its own create-once
workspace-local report and receipt.
The canonical case-semantics digest is embedded in the finalized request
filenames. A coordinated edit of the unsigned local case and its prepare
receipt therefore cannot change what gets signed.

This correction raises the prepared-case and compile schemas to v2. Older v1
verification artifacts are rejected instead of being resumed under the narrower
meaning; prepare a new v2 case from the source handoff.

For the normal reviewer-operated path, one thin coordinator runs those same
phases without adding another sender. Preparation is offline. It pauses for
the exact `RUN <campaign-id>` acknowledgement before the verifier's existing
three-request triad, and for `FINALIZE <campaign-id>` only after private review
of the verifier responses:

```bash
faultloom campaign supervise-verification-http1 \
  --source-workspace <source-workspace> --source-trusted-key <source-key> \
  --handoff <source-workspace>/verification-handoff.json \
  --verifier-workspace <verifier-workspace> --verifier-trusted-key <verifier-key> \
  --campaign-id <campaign-id> --finding-class http_response_differential \
  --claim <operator-claim> --prerequisite <operator-prerequisite> \
  --out <verifier-workspace>/verification-triad.json \
  --case <verifier-workspace>/<campaign-id>.verification-case.json \
  --private-key <0600-verifier-key-outside-both-workspaces> \
  --result-out <verifier-workspace>/verified-result.json \
  --receipt-out <verifier-workspace>/verification-compile-receipt.json
```

After verifier finalization only, it invokes the existing compile, verify, and
report commands locally. The generic report command only renders offline;
the coordinator stores the Markdown and its `draft_manual_review` receipt as
fixed create-once direct verifier-workspace files. The single JSON result names
those paths, and captured Markdown is never mixed into stdout. Resume never
resends: an unresolved or start-only verifier record stops for manual
reconciliation, and the source campaign is never run again. It does not call a
model, provider, Burp, second executor, or external submission path.

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
