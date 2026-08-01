# FaultLoom personal Windows kit

This kit contains two independent, non-installing components:

- `faultloom.exe`: signed engagement scopes, offline manual workspaces, one
  exact signed-scope direct HTTP/1.1 `GET`/`HEAD`/`OPTIONS` sender with
  owner-local reservation records and response files, optional offline Burp
  request checks,
  evidence ingestion, unverified finding drafts, and offline compilation of
  an already-produced structured model turn into a create-once candidate
  bundle.
- `windows-authority/`: the native `faultloom_ctl.exe` -> broker -> independent
  reviewer boundary for bounded local host checks.

No component registers a service, requests elevation, changes Windows policy,
or submits a security report. Run all commands from a normal PowerShell window.

## Start

```powershell
$Kit = 'C:\absolute\path\to\FaultLoom-Personal-Kit'
& "$Kit\faultloom.exe" doctor --json
& "$Kit\faultloom.exe" pack list
& "$Kit\windows-authority\faultloom_ctl.exe" local ping
```

The last command must print exactly `PONG`. An optional read-only host check is:

```powershell
& "$Kit\windows-authority\faultloom_ctl.exe" local query-service --name BFE
```

Only `BFE`, `EventLog`, and `WinDefend` are accepted. The command starts a
short-lived sibling broker and reviewer, waits for them to exit, and makes no
service configuration change.

For an authorized engagement, continue with
`windows-authority/README.md` and the scope/workspace steps in
`PERSONAL_WINDOWS_QUICKSTART.md` from the source tree. The copy of this file in
the kit intentionally summarizes the boundary; the CLI command syntax is also
available with `faultloom.exe --help`.

## Current boundary

The kit's default request path is `scope send-request`: one bounded direct
HTTP/1.1 request, no redirect follow, proxy, or retry, followed by optional
non-sensitive `evidence add-exchange` archival. A successful send completes
its reservation internally; ambiguous or no-dispatch results remain unresolved
and must not be retried. Its default output has no body preview; omit
`--body-preview-chars` (default `0`) unless a non-sensitive response is
expected and the selected provider/model is permitted to process it. Burp/browser use remains optional manual analysis.
Its `automation compile` command performs no model, provider, Burp, Gateway,
or target call; it only validates local JSON and writes a candidate-only bundle.
Automatic Gateway target dispatch (`run --live`), automatic exploitation,
remote host management, and automatic submission remain disabled.

Use `https` for hostname-only external targets. Plaintext `http` requires the
selected numeric IP to be explicitly signed as a literal hostname or covered by
a signed CIDR; add the authorized CIDR when it is not. Explicitly signed local
literal `127.0.0.1` remains supported.

`doctor --json` exposes the direct sender as the separate
`personal_direct_send_enabled`, `personal_direct_send_mode`, and
`personal_direct_send_network_access` fields. Its formal `network_access`
claim remains `none` for this Windows manual kit; it is not changed by the
personal sender.

Request reservations are an advisory guard against accidental budget overruns
while their workspace remains intact. They are not a tamper-resistant boundary.
If the optional Burp send path is selected, its separate write approval remains
that path's request-sending boundary. Never launch, close, or restart Burp.

Verify `SHA256SUMS.txt` before copying the kit to another location. Keep local
authority private keys outside this kit and outside Git or cloud-sync folders.
