# FaultLoom personal Windows quickstart

This personal beta prepares and records authorized manual Web/API or LLM/agent
research. It verifies a signed scope, creates a run workspace, stores evidence
without loading large files into memory, and creates an explicitly unverified
Markdown finding draft. Its default personal request path sends one exact,
signed-scope HTTP/1.1 request; it is not a scanner or automatic campaign.

Use only systems you own or have explicit permission to test. Replace every
example target below with the exact hostname and limits from that permission.

## 1. Set local paths

Run PowerShell as your normal Windows user, not as Administrator:

```powershell
$FaultLoom = 'C:\absolute\path\to\faultloom.exe'
$Root = Join-Path $env:USERPROFILE 'FaultLoom'
& $FaultLoom doctor --json
& $FaultLoom pack list
```

Keep the kit and engagement workspace on a local Windows drive such as `C:`.
The native Windows CLI does not support `\\wsl.localhost\...` output paths.

`web` and `llm` are the established metadata packs. The following aliases are
also available when you need a signed, manual workspace to organize candidate
research: `advanced-web`, `cloud`, `mobile`, and `web3`. They only record the
selected pack in the signed scope and workspace; they do not enable automatic
dispatch, cloud credentials, mobile-device control, or Web3 RPC.

## 2. Create your local signing key once

```powershell
& $FaultLoom key init --out-dir "$Root\authority"
```

Keep `authority-private.key` private. Do not put it in a run workspace, report,
Git repository, cloud drive, or customer delivery.

## 3. Create and sign one engagement scope

```powershell
$Job = "$Root\jobs\customer-example"
& $FaultLoom scope draft `
  --template bounty `
  --target-id target.customer-example `
  --hostname example.com `
  --port 443 `
  --scheme https `
  --method GET --method HEAD --method OPTIONS `
  --path '/*' `
  --pack web `
  --duration-hours 8 `
  --out "$Job\scope-draft.json"

& $FaultLoom scope approve "$Job\scope-draft.json" `
  --private-key "$Root\authority\authority-private.key" `
  --out "$Job\authority-grant.json"
```

## 4. Open the authorized manual workspace

```powershell
& $FaultLoom run `
  --authority "$Job\authority-grant.json" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --target target.customer-example `
  --pack web `
  --workspace "$Job\run-01"
```

Read `run-01\README.md`, then use the exact-request path below within the
signed host, port, path, method, budget, and time window. Burp Suite or a
browser remains optional manual analysis; do not use `--live`. Automatic
Gateway dispatch is not part of this personal Windows workflow.

## 5. Send one exact signed HTTP/1.1 request (default)

Create one raw HTTP/1.1 request under the private run workspace. It must use
canonical CRLF framing, exactly one matching `Host` header, no transfer
encoding, and exactly `Connection: close`. The direct sender permits only
`GET`, `HEAD`, and `OPTIONS`:

```powershell
& $FaultLoom scope send-request `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --hostname example.com `
  --port 443 `
  --scheme https `
  --method GET `
  --path '/api/profile' `
  --request-file "$Job\run-01\request.raw" `
  --response-bytes 1048576 `
  --timeout-seconds 10
```

The command first rechecks the signed workspace, trusted key, target,
`safe_probe` policy, explicit denies, execution window, byte budgets, and
exact request bytes, then makes at most one direct TCP/TLS HTTP/1.1 attempt.
It never follows redirects, uses a proxy, retries, or sends a second request.
The smaller of the signed per-request limits and 65,536 request bytes / 1 MiB
response bytes applies. One absolute timeout covers reservation recheck, DNS,
connect, TLS, send, and receive. The accepted response subset rejects every
`Transfer-Encoding` and interim `1xx` response; `HEAD`, `204`, `205`, and `304`
must have no body bytes; otherwise a matching `Content-Length` is accepted, as
is a close-delimited response that ends at EOF. A successful JSON result has schema
`faultloom.personal-http1-send.v1`, `dispatchPerformed: true`, a reservation,
response metadata, and a raw `responseFile` under
`$Job\run-01\responses`. The command completes that reservation internally;
do **not** run `scope complete-request` again for this success path.

Use `https` for a hostname-only external target. A plaintext `http` send
requires the selected numeric IP to be explicitly signed as a literal hostname
or covered by a signed CIDR; otherwise add the authorized CIDR to the scope.
An explicitly signed local literal such as `127.0.0.1` remains supported.

The default result deliberately contains no response body preview. Leave
`--body-preview-chars` omitted (equivalent to `0`) and inspect the private
response file locally. `--body-preview-chars 1` through `3072` is explicit
opt-in and only appropriate after the operator has confirmed both a
non-sensitive response expectation and permission for the selected
provider/model to process that response; the supervised project skill then
uses `3072` as its bounded maximum.

Connection or TLS setup failure returns a structured
`dispatchPerformed: false` / `unresolved_no_retry` result. A partial,
malformed, oversized, or otherwise ambiguous result returns structured
`response_incomplete_or_ambiguous` with `dispatchPerformed: true`. In either
case the reservation remains unresolved: do not retry, substitute a zero-byte
response, or issue another request. Stop for operator reconciliation.

The response file is private, untrusted data. Classify it before archival. If
it contains credentials, tokens, PII, customer data, or other sensitive
material, delete it before adding evidence unless the engagement requires
retention; record only a non-sensitive stop reason and reservation ID.

The owner-local reservation database is an advisory accidental-overrun guard,
not a tamper-resistant boundary. It never widens the signed scope.

`doctor --json` reports direct-sender capability separately as
`personal_direct_send_enabled`, `personal_direct_send_mode`, and
`personal_direct_send_network_access`. Do not treat those fields as a formal
live-Gateway claim: the existing `network_access` field remains `gateway_only`
for the controller-provisioned POSIX path or `none` for the Windows manual
package.

This accounting begins with RC6. A workspace created by RC5 predates it and
must not be reused: create a fresh signed run workspace instead. There is
intentionally no reset or migration command.

## 6. Run a bounded HTTP/1.1 triad (optional)

When one exact request has produced a candidate that needs a minimal
reproduction check, use the supervised triad. Prepare two raw HTTP/1.1 files
next to the spec: `effect.raw` and `control.raw`. They must have the same
method, HTTP version, headers, `Host`, and body; their request-target lines
must be the only difference. The effect file is intentionally reused for the
second (reproduction) send.

The spec is strict and binds the engagement's external authorization record;
the reference and digest are an audit trail, not a substitute for the signed
FaultLoom scope:

```json
{
  "schema": "faultloom.personal-http1-triad.v1",
  "campaign_id": "example-loopback-triad-01",
  "authorization_reference": "example-loopback-approval-2026-08",
  "authorization_document_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "hostname": "127.0.0.1",
  "port": 8000,
  "scheme": "http",
  "timeout_seconds": 10,
  "requests": [
    {"role": "effect", "method": "GET", "path": "/example", "request_file": "effect.raw", "response_bytes": 1048576},
    {"role": "negative_control", "method": "GET", "path": "/example-control", "request_file": "control.raw", "response_bytes": 1048576}
  ],
  "finding": {
    "title": "Example loopback candidate",
    "severity": "low",
    "summary": "Example only; replace with an observed candidate.",
    "impact": "Example only; do not treat this text as a finding.",
    "remediation": "Example only; replace with a concrete remediation."
  }
}
```

If this triad corresponds to a candidate in an existing private
`automation compile` result bundle, bind that exact candidate first. The
output must stay beside `triad.json`, `effect.raw`, and `control.raw`:

```powershell
& $FaultLoom campaign prepare-http1-triad `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --template "$Job\run-01\triad.json" `
  --result "$Job\run-01\automation\result.<digest>\result.json" `
  --receipt "$Job\run-01\automation\result.<digest>\receipt.json" `
  --candidate-id 'candidate.from-result' `
  --out "$Job\run-01\triad.bound.json"
```

This is offline preparation only. It rechecks the workspace/grant, exact
result and receipt, admitted-plan authority when applicable, candidate intent, template, and
both request digests. It does not call a model, provider, Burp, or target and
does not claim verification. Review the output and use `triad.bound.json` for
the run. The selected ID may name an admitted plan or the result's single
compiled safe-PoC step; either must be exactly `safe_probe` + `http.semantic`.
If there is no automation result bundle, the original reviewed v1
`triad.json` remains valid.

The preferred bound-candidate path combines prepare, run, and offline finalize
behind two explicit review pauses:

```powershell
& $FaultLoom campaign supervise-http1-triad `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --template "$Job\run-01\triad.json" `
  --result "$Job\run-01\automation\result.<digest>\result.json" `
  --receipt "$Job\run-01\automation\result.<digest>\receipt.json" `
  --candidate-id 'candidate.from-result' `
  --out "$Job\run-01\triad.bound.json"
```

After reviewing the bound spec, type exactly `RUN <campaign-id>`. After the
three private response files are written, inspect them and type exactly
`FINALIZE <campaign-id>` only when they are non-sensitive. Prompts are on
stderr; stdout is one JSON result suitable for capture. You may exit and rerun
the same command at either review checkpoint. Never rerun an unresolved or
possibly started dispatch: the command reports manual reconciliation instead,
and reports a start-only crash as dispatch state `unknown`.

The separate commands below are the equivalent manual phase controls.

Run the reviewed v1 or bound v2 spec from the signed workspace:

```powershell
& $FaultLoom campaign run-http1-triad `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --spec "$Job\run-01\triad.bound.json"
```

The command creates a start record before target I/O, then sends exactly three
requests sequentially (effect, the same effect again, control). It performs no
preview, retry, redirect, proxy, provider/model call, Burp action, evidence
archival, or submission. A connection/TLS failure, rate limit, partial,
malformed, or ambiguous response stops with `unresolved_no_retry`; do not
retry or fabricate a completion. Inspect all private response files before
continuing. If any contains credentials, tokens, PII, customer data, or other
sensitive material, stop and delete/quarantine it according to the
engagement's retention rule.

For a bound v2 spec, all result/receipt/template/request sources are re-read
before the start record and socket. A changed source fails closed; the exact
captured request bytes are the bytes admitted and sent.

Only after that review, finalize offline:

```powershell
& $FaultLoom campaign finalize-http1-triad `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --campaign-id example-loopback-triad-01 `
  --confirm-reviewed-non-sensitive
```

Finalization opens no socket. It verifies the signed workspace and all request,
response, and body digests, archives exactly three exchanges, and applies only
`exact_body_digest_v1`. Equal effect/reproduction body digests with a
different control digest produce an evidence-bound `draft_unverified` finding
draft; otherwise the durable result is `negative_campaign` and no finding is
created. Neither outcome is independent verification or proof of a
vulnerability. Review the draft, reproduce independently, and submit manually.

## 7. Archive the completed request/response exchange

For a confirmed non-sensitive direct result, preserve the exact request and
response pair with the already-completed reservation:

```powershell
& $FaultLoom evidence add-exchange `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --reservation-id 'reservation.from-send-request' `
  --request-file "$Job\run-01\request.raw" `
  --response-file "$Job\run-01\responses\reservation.personal-http1.raw"
```

This is offline archival only. It re-verifies the signed workspace (including
after the execution window for archival), reloads the completed reservation,
and requires the exact stored request and response SHA-256 values and lengths.
It rejects symlinks, changed files, incomplete or count-only completions, then
copies both files to `evidence\raw` and writes one evidence record. It does not
send a request, invoke Burp, verify a finding, or invent a vulnerability.

## Optional Burp analysis

Burp remains useful for manual inspection and exact-tool analysis, but it is
not the default request sender. Never launch, close, or restart Burp. If the
owner chooses its exact MCP send path, require the separately documented
`scope verify-request` admission and its own write approval; do not fall back
to a generic Burp sender or combine that path with an existing direct-send
reservation.

## 8. Add other exported evidence

Export requests/responses, notes, or screenshots from your tool, then record
each file:

```powershell
& $FaultLoom evidence add `
  --workspace "$Job\run-01" `
  --file 'C:\path\to\burp-export.json' `
  --kind burp `
  --title 'Unauthorized account response'
```

Evidence is copied into `evidence\raw` with a SHA-256 sidecar. Review exports
for passwords, cookies, tokens, API keys, and unnecessary personal data before
sharing them.

## 9. Create a submission draft

Put exact reproduction steps in a UTF-8 text file, then run:

```powershell
& $FaultLoom finding new `
  --workspace "$Job\run-01" `
  --title 'Unauthenticated account data exposure' `
  --severity high `
  --summary 'A public request returns another account record.' `
  --impact 'An unauthenticated party can read private account data.' `
  --steps-file 'C:\path\to\steps.txt' `
  --remediation 'Enforce object-level authorization before serialization.'
```

The Markdown file in `findings\` is a draft. Reproduce the issue, remove
secrets, match the program's severity rubric, and submit it yourself through
the customer's or bounty program's official channel.

## 10. Optional offline model-turn handoff and compilation

First create the exact request from the completed exchange archived in step 7.
The excerpt file must already be operator-redacted and non-sensitive:

```powershell
# One-time setup; keep this private key outside every run workspace.
& $FaultLoom key init --out-dir "$Root\disclosure-approver"

& $FaultLoom automation prepare-http1-request `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --evidence-id 'evidence.from-add-exchange' `
  --excerpt-file "$Job\run-01\redacted-observation.txt" `
  --provider-id 'provider.approved-by-grant' `
  --disclosure-private-key "$Root\disclosure-approver\authority-private.key" `
  --hostname 'exact.authorized.host' --port 443 --scheme https `
  --method GET --path '/exact/request-target' `
  --out "$Job\run-01\automation-request.json" `
  --confirm-redacted-non-sensitive
```

This revalidates the exact archived bytes, completed reservation fingerprint,
active signed window, target, policy, deny list, and provider before creating a
private file once. It makes no target or provider call.

To prepare an offline prompt for a model UI, local CLI, or official API without
configuring a FaultLoom provider, export a private handoff from the exact signed
request:

```powershell
& $FaultLoom automation export-handoff `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --request 'C:\path\to\automation-request.json' `
  --provider-id 'provider.approved-by-grant' `
  --model-snapshot 'exact.snapshot.approved-by-grant' `
  --trusted-disclosure-key "$Root\disclosure-approver\authority-public-key.json" `
  --out 'C:\path\to\model-handoff.json'
```

The export requires `provider_network_access=none`; it creates the handoff once
with private permissions and does not contact a provider, Burp, a Gateway, or a
target. The provider ID and exact model snapshot must be permitted by the signed grant, and the supplied
disclosure public key(s) must verify every redacted excerpt for that provider at
the workspace's active time. Give that file only to the approved provider/service
and save exactly one returned function-arguments object as `model-turn.json`.
The handoff contains no credentials, cookies, or provider connection
configuration, and does not attest the model. Redacted evidence can still
contain a target URL or other target details, so do not send it to a different
provider.

If Codex or another model client has already produced an exact FaultLoom
`AutomationRequest` and structured `ModelTurn` JSON file, compile them inside
the same signed workspace:

```powershell
& $FaultLoom automation compile `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --request 'C:\path\to\automation-request.json' `
  --model-turn 'C:\path\to\model-turn.json'
```

This command requires `provider_network_access` to be `none`. It does not call
the model, Burp, a Gateway, or the target. It rechecks the current signed scope
and writes a create-once result bundle under `run-01\automation`. A generated
`candidate.md` is still unverified and cannot be treated as a confirmed
finding or submitted automatically.

### Archived-exchange model HTTP/1 PoC supervisor

When the model turn contains one bounded safe-PoC proposal for the exact
archived exchange, the operator can compile and supervise its three-request
comparison in one command. Prepare a strict metadata file yourself; it must
contain the campaign ID, external authorization reference and its SHA-256,
exact endpoint, timeout and response limit, and the operator-authored finding
fields. The model turn cannot provide raw request bytes or finding prose:

```powershell
$ModelPocOut = "$Job\run-01\model-http1-poc"
& $FaultLoom campaign supervise-model-http1-poc `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --request "$Job\run-01\automation-request.json" `
  --model-turn 'C:\path\to\external-model-turn.json' `
  --evidence-id '<archived-exchange-evidence-id>' `
  --negative-control-path '/operator-chosen-control-target' `
  --metadata 'C:\path\to\operator-model-http1-metadata.json' `
  --out $ModelPocOut
```

The command performs deterministic offline compilation of zero generic actions
and exactly one safe-PoC step. It uses the archived effect request bytes
exactly and derives `control.raw` by changing only the request-target line.
The private create-once bundle is keyed by its source digests. Its provenance
records the external authorization reference as
`operator_asserted_unverified`, while the signed grant and run remain separate
verified bindings. Review the generated triad, type exactly `RUN <campaign-id>`,
inspect all three private responses, then type exactly
`FINALIZE <campaign-id>` only when they are non-sensitive. It sends exactly
effect, the same effect as reproduction, and the derived control, with no
retry. Resume is durable and never replays completed sends; unresolved or
start-only state stops for manual reconciliation. No provider, Gateway, Burp,
or submission is called, and independent verification/reporting remains a
separate downstream step.

The command help also lists `automation provider-turn`. That direct official
API path is intentionally POSIX-only because its durable receipt and state
files rely on no-follow opens, owner-only permissions, file locking, and
directory sync. Use the signed workflow documented in
`docs/OPENAI_COMPATIBLE_PROVIDERS.md` from WSL/Linux. Native Windows fails
closed; use the offline handoff and compilation flow above there instead.

## 11. Independent HTTP/1 replay and manual-review report

The personal package can independently replay a finalized `draft_unverified`
campaign without adding another sender. First export the source handoff, then
create a second
manual workspace from a separately signed verifier grant. The verifier must
have a different actor, key, authority, and workspace while naming the exact
same target:

```powershell
& $FaultLoom campaign export-verification-handoff `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --campaign-id '<campaign-id>' `
  --out "$Job\run-01\verification-handoff.json"

& $FaultLoom campaign prepare-verification-http1 `
  --source-workspace "$Job\run-01" `
  --source-trusted-key "$Root\authority\authority-public-key.json" `
  --handoff "$Job\run-01\verification-handoff.json" `
  --verifier-workspace '<separate-verifier-workspace>' `
  --verifier-trusted-key '<separate-verifier-public-key>' `
  --campaign-id '<campaign-id>' `
  --finding-class '<class>' `
  --claim '<exact claim>' `
  --prerequisite '<exact prerequisite>' `
  --out '<separate-verifier-workspace>\verification-triad.json'
```

The preferred package path coordinates those existing phases behind the same
two explicit review pauses:

```powershell
$Verifier = '<separate-verifier-workspace>'
$VerifierAuthority = '<separate-verifier-authority-directory>'
$Campaign = '<campaign-id>'

& $FaultLoom campaign supervise-verification-http1 `
  --source-workspace "$Job\run-01" `
  --source-trusted-key "$Root\authority\authority-public-key.json" `
  --verifier-workspace $Verifier `
  --verifier-trusted-key "$VerifierAuthority\authority-public-key.json" `
  --handoff "$Job\run-01\verification-handoff.json" `
  --out "$Verifier\verification-triad.json" `
  --case "$Verifier\$Campaign.verification-case.json" `
  --private-key "$VerifierAuthority\authority-private.key" `
  --result-out "$Verifier\verified-result.json" `
  --receipt-out "$Verifier\verification-compile-receipt.json" `
  --campaign-id $Campaign `
  --finding-class '<class>' `
  --claim '<exact claim>' `
  --prerequisite '<exact prerequisite>'
```

Review the generated verifier triad and type exactly `RUN <campaign-id>` before
target I/O. Review the three private response files and type exactly
`FINALIZE <campaign-id>` before offline compilation. The command then invokes
the existing verifier and renders a digest-named `draft_manual_review` report
inside the verifier workspace. It never submits externally. A completed rerun
does not resend or recompile; an unresolved, start-only, or partially finalized
state stops for manual reconciliation.

The separate manual controls remain available: run the generated verifier triad
with the existing `campaign run-http1-triad`, review all three fresh responses,
and finalize it with `campaign finalize-http1-triad`. The verifier slice accepts
only bodyless `GET` or `OPTIONS` requests with `Host` and `Connection: close`,
sends exactly three sequential requests, and never retries.

Then run `campaign compile-verification-http1` using the paths emitted by the
prepare result. The compile result prints the exact arguments for the existing
`faultloom verify` and `faultloom report` commands. All three operations are
offline. A successful verdict still produces only a `draft_manual_review`
outbox; inspect and submit it yourself through the authorized customer or
program channel.

## Current boundary

Ready now: signed scopes, manual authorized workspaces, bounded evidence
ingestion, SHA-256 records, exact raw-request binding for offline Burp
handoffs, and finding drafts.
An already-produced structured model turn can also be compiled offline into a
private candidate bundle with no provider or target access.
Within an intact workspace, request checks persist advisory owner-local
reservations and reject additional reservations that exceed the recorded signed
total, 60-second rate, active concurrency, or per-request byte budgets. A
completion rechecks the reserved request digest and records either the
operator-observed response byte count or a locally captured response digest,
then releases concurrency. If the observed response exceeds its reserved budget,
FaultLoom records that fact and returns an authorization failure after emitting the
result.
Linux-only durable resume, automatic Gateway target dispatch, destructive or
unbounded exploitation, and automatic external submission are not enabled in
this Windows personal beta.
