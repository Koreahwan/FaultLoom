# FaultLoom runtime

This package provides the public `faultloom` command-line surface and the
durable research runtime. The v0.1 CLI starts fail closed: its loopback smoke
path validates a signed authority grant without opening a socket, and live
dispatch remains unavailable until the Gateway execution path is integrated.

Trusted authority keys are local public-key records. Pass one to `faultloom
run` with `--trusted-key`, or set `FAULTLOOM_TRUSTED_AUTHORITY_KEY` to its
path. Raw private keys and credentials are never accepted by this command.

Authority and trusted-key inputs must be regular, single-link files reached
without symlink or parent traversal. The CLI opens and binds both files before
reading either one, applies a one-mebibyte and bounded-JSON-depth limit, and
fails if either path or file metadata changes during capture. Loopback smoke
targets use canonical lowercase ASCII `localhost` names or canonical loopback
IP addresses; ambiguous hostname spellings are denied.
