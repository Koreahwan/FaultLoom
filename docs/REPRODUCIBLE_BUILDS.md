# Reproducible and offline builds

FaultLoom Core's release-candidate builder is deliberately network-free. It
uses the pinned Python standard library to assemble pure-Python wheels and a
tracked-source archive. It never invokes a package build backend, downloads a
dependency, or reads an untracked file.

From a clean checkout with the pinned Python and Rust toolchains already
installed, run:

```bash
python3 tools/verify_clean_checkout.py
```

If the exact Rust version is exposed through an alias rather than its version
name, select that preinstalled alias without changing the expected version:

```bash
FAULTLOOM_RUST_TOOLCHAIN=stable python3 tools/verify_clean_checkout.py
```

The verifier forces package-manager offline flags, validates the dependency
lock and pinned CI action revisions, builds twice with `SOURCE_DATE_EPOCH` set
to the checked-out commit time, and byte-compares every artifact. Artifacts
include root `LICENSE` and `NOTICE` files, a CycloneDX SBOM, an in-toto
provenance statement, and `SHA256SUMS`.

## Dependency admission

`requirements-release.lock` is the only release-environment lock. It is empty
while the repository has no external runtime dependencies. Once a discovered
package declares one, the verifier refuses to build until the lock contains an
exact `name==version` requirement with at least one
`--hash=sha256:<digest>`. URLs, local paths, editable installs, mutable
versions, and unhashed entries are rejected. Build backends are not executed;
their requirements must still be exact pins so metadata cannot silently drift.

The developer snapshot in `requirements-dev.lock` is not consumed by release
or CI builds. A later test-environment admission task must replace that
snapshot with a platform-complete hashed lock before CI may install it.

## Release remains disabled

The public build policy has `release_enabled = false`. The builder can produce
reproducible release-candidate artifacts, but release mode fails closed. T41
may enable it only after the signed human authorization verifier, SBOM and
provenance gates, private evaluation receipt, and exact artifact digest checks
are integrated. This repository contains no publishing step or credential.

