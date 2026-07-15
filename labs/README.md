# FaultLoom public loopback labs

This directory contains original, deterministic fixtures that bind only to
`127.0.0.1`. The baseline fixture makes no outbound connection and uses inert
canary state that is reset before and after a clean replay.

`manifest.v1.json` describes both a vulnerable positive and denied negative
control. Future Web/API/LLM/patch fixtures may add their own versioned documents
through the namespaced descriptor reference without changing this base contract.

Direct HTTP clients are permitted only to diagnose fixture health. A run can
count as evidence only through `bind_gateway_evidence`, with an `ActionIntent`
and already-authenticated, completed Target Gateway `DispatchReceipt` bound to
the manifest target, actor tenant, operation, response oracle, action, and run
digest.

The fixture is purpose-built for FaultLoom and does not copy proprietary labs.
