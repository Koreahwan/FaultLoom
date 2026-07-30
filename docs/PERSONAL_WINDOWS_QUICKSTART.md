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

## 5. Check a request before Burp sends it

Before a model or operator sends a request through Burp, validate the exact
request metadata against the signed workspace:

```powershell
& $FaultLoom scope check-request `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --hostname example.com `
  --port 443 `
  --scheme https `
  --method GET `
  --path '/api/profile' `
  --request-bytes 2048 `
  --response-bytes 1048576
```

Continue only when the JSON result says `"authorized": true`. This command
rechecks the workspace's signed authority against the public key kept outside
that workspace, plus its target, `safe_probe` action policy, explicit denies,
execution window, and per-request byte limits. It atomically creates an
owner-local request reservation and returns its `reservation_id`, expiry, and
remaining signed action, rate, and concurrency budgets. It opens no socket and
does not call Burp.

After Burp has sent the request, record the observed response size and release
the reservation's concurrency slot. Use the returned `reservation_id` and do
not include a request or response body in this command:

```powershell
& $FaultLoom scope complete-request `
  --workspace "$Job\run-01" `
  --trusted-key "$Root\authority\authority-public-key.json" `
  --reservation-id 'reservation.from-check-request' `
  --observed-response-bytes 12345
```

This is advisory owner-local accounting, not tamper-resistant enforcement: any
process able to modify the workspace can reset or replace its accounting state.
It does not grant Burp permission. Burp request-sending and settings tools
retain their separate `writes` approval requirement, which remains the hard
send boundary.

This accounting begins with RC6. A workspace created by RC5 predates it and
must not be reused: create a fresh signed run workspace instead. There is
intentionally no reset or migration command.

## 6. Add exported evidence

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

## 7. Create a submission draft

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

## Current boundary

Ready now: signed scopes, manual authorized workspaces, bounded evidence
ingestion, SHA-256 records, metadata checks for Web, LLM, and the registered
candidate packs, offline Burp request scope checks, and finding drafts.
Within an intact workspace, request checks persist advisory owner-local
reservations and reject additional reservations that exceed the recorded signed
total, 60-second rate, active concurrency, or per-request byte budgets. A
completion records only the operator-observed response byte count and releases
concurrency. If the observed response exceeds its reserved budget, FaultLoom
records that fact and returns an authorization failure after emitting the
result.
Linux-only durable resume, automatic
Gateway target dispatch, automatic exploitation, and automatic external
submission are not enabled in this Windows personal beta.
