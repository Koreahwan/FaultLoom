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

## 6. Archive the completed request/response exchange

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

## 7. Add other exported evidence

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

## 8. Create a submission draft

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

## 9. Optional offline model-turn handoff and compilation

To prepare an offline prompt for a model UI, local CLI, or official API without
configuring a FaultLoom provider, export a private handoff from the exact signed
request:

```powershell
& $FaultLoom automation export-handoff `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --request 'C:\path\to\automation-request.json' `
  --provider-id 'provider.approved-by-grant' `
  --trusted-disclosure-key "$Root\authority\disclosure-approver-public-key.json" `
  --out 'C:\path\to\model-handoff.json'
```

The export requires `provider_network_access=none`; it creates the handoff once
with private permissions and does not contact a provider, Burp, a Gateway, or a
target. The provider ID must be permitted by the signed grant, and the supplied
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
Linux-only durable resume, automatic
Gateway target dispatch, automatic exploitation, and automatic external
submission are not enabled in this Windows personal beta.
