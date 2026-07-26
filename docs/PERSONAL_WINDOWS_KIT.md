# FaultLoom personal Windows kit

This kit contains two independent, non-installing components:

- `faultloom.exe`: signed engagement scopes, offline manual workspaces,
  evidence ingestion, and unverified finding drafts.
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

The kit is usable for manual Burp/browser work within a signed scope. Automatic
Gateway target dispatch (`run --live`), automatic exploitation, remote host
management, and automatic submission remain disabled.

Verify `SHA256SUMS.txt` before copying the kit to another location. Keep local
authority private keys outside this kit and outside Git or cloud-sync folders.
