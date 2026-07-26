# Controller-provisioned Gateway handoff

`provision_gateway_handoff()` packages one existing signed FLBS bootstrap, one
digest-pinned Gateway executable, an existing authenticated journal FD pair,
an existing channel configuration, and one preapproved
`GatewayDispatchCommand`. It does not generate or sign any of those authority
objects.

Keep the returned `GatewayProvisionedHandoff` open while starting the
`faultloom run --live` child. Pass `handoff.pass_fds` through the child process,
and supply `handoff.bundle_path` and `handoff.command_path` as
`--gateway-bundle` and `--dispatch-command`. Close the handoff after the child
exits; closing removes the private bundle and command and closes the retained
journal descriptors.

This is a one-run POSIX controller seam. It does not install a service, create
controller trust, issue a grant or lease, start an authenticated journal, or
make an external request by itself.

## Owned-loopback integration proof

`gateway/tests/provisioned_handoff.rs` exercises the equivalent installed
handoff with the exact Cargo-built `faultloom-gateway`: test-only controller
helpers generate a signed FLBS and trust store, admit a signed epoch, connect
authenticated journal FIFOs, dispatch once to an owned `127.0.0.1` listener,
verify the HTTP receipt and durable journal state, and reject a changed target
without a second connection. Authority minting remains under `gateway/tests/`
and is not exported by the production crate or Python runtime.

The Python provisioner cannot directly run that test trust setup: the installed
Gateway intentionally reads `/etc/faultloom/gateway-trust-v1.json`, while the
test injects that file with Bubblewrap before executing the exact binary. A
production controller must therefore supply the real installed trust store,
signed FLBS, authenticated journal service/FDs, channel configuration, and
already-issued decision/lease. Treating the JSON bundle alone as reusable is
invalid because its FD numbers are meaningful only while the provisioning
controller owns and passes those descriptors.

On POSIX, `faultloom doctor --json` reports this narrowly as
`live_dispatch_enabled: true`,
`live_dispatch_mode: "controller_provisioned_single_dispatch"`, and
`network_access: "gateway_only"`. Those fields describe the supported handoff
contract; they do not claim that a bundle, journal sidecar, or approved command
has already been provisioned. The Windows personal executable remains
`manual_only`, with live dispatch disabled and `network_access: "none"`.
