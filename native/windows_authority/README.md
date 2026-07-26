# FaultLoom Windows Authority MVP

This is a non-installing Windows x64 package. It does not register a service, request elevation, change service configuration, or persist a process. Run it as a standard user from an ordinary Command Prompt or PowerShell window.

Use the absolute path to the packaged control executable:

```text
C:\absolute\path\faultloom_ctl.exe local ping
C:\absolute\path\faultloom_ctl.exe local query-service --name BFE
```

`local ping` prints exactly `PONG` and exits 0. `local query-service` accepts only `BFE`, `EventLog`, or `WinDefend`. It prints `SERVICE_STATUS` followed by nine unsigned decimal fields and exits 0 when the read-only query succeeds. If an allowlisted service is absent or cannot be queried, it may instead print exactly `ACTION_FAILED` and exit 7.

Each local command starts the sibling `faultloom_broker.exe`, which starts the sibling `faultloom_reviewer.exe`. The control process verifies both retained process image paths, performs one request through the authenticated local pipes, signals shutdown, and waits for both processes and pipes to disappear. The entire command is bounded to ten seconds. Closing the control process also closes a kill-on-close Job that contains the child processes.

Exit 1 means the command line was rejected. Other nonzero exits indicate startup, authentication, protocol, deadline, or cleanup failure. Verify that all seven package members remain together and unchanged, then retry from a standard-user console. Do not rename or substitute an executable, run from a partial copy, install these binaries, or register them with the Service Control Manager.
