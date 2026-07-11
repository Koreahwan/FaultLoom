# FaultLoom runtime

This package provides the public `faultloom` command-line surface and the
durable research runtime. The v0.1 CLI starts fail closed: its loopback smoke
path validates a signed authority grant without opening a socket, and live
dispatch remains unavailable until the Gateway execution path is integrated.

Trusted authority keys are local public-key records. Pass one to `faultloom
run` with `--trusted-key`, or set `FAULTLOOM_TRUSTED_AUTHORITY_KEY` to its
path. Raw private keys and credentials are never accepted by this command.
