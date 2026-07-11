# faultloom-sdk

`faultloom-sdk` admits versioned pack and adapter manifests and exchanges typed
JSON messages with isolated local processes. It never loads a Python plugin
module in the FaultLoom process and never issues an `ActionLease` or a target
dispatch authorization.

The bundled reference process is deliberately non-networked. It demonstrates
manifest discovery, deterministic action compilation, and observation
normalization over stdin/stdout. Compiled actions remain non-dispatchable until
the separate Gateway validates signed authority, current scope, and a lease.

`ManifestRegistry` admits capability, compiler, normalizer, hypothesis,
verifier, and evaluation descriptors from separate catalogs. Adapter schema
digests cover the complete typed request and response JSON Schemas.
