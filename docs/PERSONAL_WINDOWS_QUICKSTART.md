# FaultLoom personal Windows quickstart

This personal beta prepares and records authorized manual Web/API or LLM/agent
research. It verifies a signed scope, creates a run workspace, stores evidence
without loading large files into memory, and creates an explicitly unverified
Markdown finding draft. These commands do not perform automatic network
dispatch.

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

Read `run-01\README.md`, then use Burp Suite or a browser manually within the
signed host, port, path, method, budget, and time window. Do not use `--live`;
automatic Gateway dispatch is not part of this personal Windows beta.

## 5. Bind the exact request before Burp sends it

Export the single raw HTTP/1.1 request from Burp to a local file, then bind its
exact bytes before the manual handoff. Run this immediately before sending; it
does not send anything itself:

```powershell
& $FaultLoom scope verify-request `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --hostname example.com `
  --port 443 `
  --scheme https `
  --method GET `
  --path '/api/profile' `
  --request-file 'C:\path\to\burp-request.raw' `
  --response-bytes 1048576
```

Continue only when the JSON result says `"authorized": true`. This command
rechecks the workspace's signed authority against the public key kept outside
that workspace, plus its target, `safe_probe` action policy, explicit denies,
execution window, and per-request byte limits. It accepts only one regular,
non-symlink raw HTTP/1.1 file with canonical CRLF framing, one `Host` header,
and no transfer encoding; its request line and Host must match the supplied
signed endpoint metadata. It atomically records the SHA-256 and byte length in
an owner-local request reservation and returns its `reservation_id`, expiry,
and remaining budgets. It opens no socket and does not call Burp.

After Burp has sent the request, provide the same raw request file again. The
completion re-hashes it before releasing the reservation's concurrency slot;
any method, path, Host, header, or body change fails closed. A response file is
optional, but binds the recorded response length and SHA-256 without printing
its contents. A response file larger than the reserved response limit is
rejected; use `--observed-response-bytes` when only the length is available:

```powershell
& $FaultLoom scope complete-request `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --reservation-id 'reservation.from-verify-request' `
  --request-file 'C:\path\to\burp-request.raw' `
  --response-file 'C:\path\to\burp-response.raw'
```

If the response is not available as a file, replace `--response-file` with
`--observed-response-bytes 12345`. Expired reservations cannot be completed.

This is advisory owner-local accounting, not tamper-resistant enforcement: any
process able to modify the workspace can reset or replace its accounting state.
It does not grant Burp permission. Burp request-sending and settings tools
retain their separate `writes` approval requirement, which remains the hard
send boundary.

This accounting begins with RC6. A workspace created by RC5 predates it and
must not be reused: create a fresh signed run workspace instead. There is
intentionally no reset or migration command.

## 6. Archive the completed request/response exchange

When `scope complete-request` used `--response-file`, preserve that exact
request and response pair with the completed reservation:

```powershell
& $FaultLoom evidence add-exchange `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --reservation-id 'reservation.from-verify-request' `
  --request-file 'C:\path\to\burp-request.raw' `
  --response-file 'C:\path\to\burp-response.raw'
```

This is offline archival only. It re-verifies the signed workspace (including
after the execution window for archival), reloads the completed reservation,
and requires the exact stored request and response SHA-256 values and lengths.
It rejects symlinks, changed files, incomplete or count-only completions, then
copies both files to `evidence\raw` and writes one evidence record. It does not
send a request, invoke Burp, verify a finding, or invent a vulnerability.

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
