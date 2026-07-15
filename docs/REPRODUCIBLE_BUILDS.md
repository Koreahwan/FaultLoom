# Reproducible builds with offline-requested execution

FaultLoom Core's release-candidate builder has no download or package-install
operation. It uses the version-selected Python standard library to assemble pure-Python
wheels and a tracked-source archive without invoking a package build backend. It also
builds the separately named `faultloom-gateway-0.1.0-x86_64-unknown-linux-gnu`
release ELF with pinned Cargo and rustc from an immutable source snapshot.
Build inputs are read from immutable blobs in the checked-out Git `HEAD`, not
from worktree files. Ignored and untracked files therefore cannot enter an
artifact. `assume-unchanged` and `skip-worktree` index flags are rejected so a
hidden worktree mutation cannot masquerade as a clean checkout.
Replace refs, grafts, inherited `GIT_*` overrides, and lazy object fetching are
disabled or rejected. The verifier recomputes every commit, tree, and blob
object ID from its type, length, and content. It parses tree objects recursively
from those verified bytes and requires canonical modes, ordering, basename-only
UTF-8 entries, and unique logical paths instead of trusting a flattened
`git ls-tree` view.

From a clean checkout with the selected Python and pinned Rust toolchains already
installed, run:

```bash
python3 tools/verify_clean_checkout.py
```

If the exact Rust version is exposed through an alias rather than its version
name, select that preinstalled alias without changing the expected version:

```bash
FAULTLOOM_RUST_TOOLCHAIN=stable python3 tools/verify_clean_checkout.py
```

The verifier requests offline behavior through package-manager environment
flags, validates the dependency lock and pinned CI action revisions, resolves
the selected compiler from the preinstalled rustup toolchain directory,
compiles and runs a randomized native
Rust probe, invokes Cargo with `--frozen --locked --offline`, builds twice with
`SOURCE_DATE_EPOCH` set to the checked-out commit time, and compares every artifact
byte and file mode. The verifier then independently rebuilds all primary artifacts a
third time while reconciling metadata. Offline flags
are not network isolation: provenance records `offline_requested` with
`enforced = false`. Release mode requires a separately enforced isolation
boundary and fails closed while that boundary is absent.

The Rust verifier is admitted only for the pinned
`x86_64-unknown-linux-gnu` host. It hashes the exact selected compiler and
compares it with `rustc_sha256` before execution. It also reconciles
`rustc_closure_sha256` over the compiler, `librustc_driver`, bundled LLVM, and
the host sysroot. The verifier copies that closure into a private staged
snapshot, checks the staged compiler and closure again, removes write bits,
and invokes only the staged compiler with a minimal environment that excludes
loader and compiler override variables. Gateway builds additionally require Cargo
from that same toolchain; its binary is checked against `[gateway].cargo_sha256`,
copied into the private stage, and its verbose version, host, commit, and date are
validated. The verifier reconciles the compiler identity, runs the semantic probe,
and re-hashes rustc, Cargo, and the staged closure after all builds.
The modes are a mutation guard, not an OS-enforced immutable mount; admission
therefore also requires the canonical CI workflow below to exclude arbitrary
repository-controlled code before the gate. Release remains disabled until an
independent isolation boundary is available.

CI admits one byte-exact canonical workflow. It fixes the checkout repository,
revision, destination, cleanup behavior, and credential policy; fixes every
action digest and input; admits only the exact Rust provisioning command before
the gate; and runs `python3 tools/verify_clean_checkout.py` from the repository
root. This strict template also excludes custom shells, working directories,
environment-function injection, duplicate keys, and YAML scalar folding rather
than trying to infer their GitHub execution semantics with a permissive parser.
This is a repository self-check, not an external trust anchor: a future change
could replace both the workflow and its validator. SBOM and provenance record
the canonical workflow SHA-256 and `external_trust_anchor = false`. Branch
protection must require a trusted
workflow or ruleset outside the candidate revision before this check can serve
as release evidence; release mode remains disabled while that receipt is absent.
The verifier reconstructs the full CycloneDX component/dependency graph and SLSA
provenance predicate from Git inputs and rejects partial or marker-only metadata.
The Gateway is an independent `pkg:cargo/faultloom-gateway@0.1.0` application
component and provenance subject, bound to the Git commit/tree, Cargo lock digest,
build-recipe digest, target, rustc closure, and exact rustc/Cargo digests. Host linker,
libc, dynamic-loader, and kernel bytes remain explicitly `unverified`; therefore this
is still a reproducibility candidate rather than a hermetic release receipt. Artifacts
include root `LICENSE` and `NOTICE` files and `SHA256SUMS`.

The explicit `[gateway]` and `[cargo_vendor]` policies admit exactly the root workspace
manifest, lock, Gateway package manifest, deterministic release profile, four exact direct
pins with default features disabled (`base64` and `ed25519-dalek` with no features,
`serde` with `derive,std`, and `serde_json` with `std`), and one generated crates.io source
replacement. The current lock contains 31 registry
packages and 43 dependency edges. Its registry package set must be bijective with the
versioned directories under `vendor/`. Every lock checksum must equal the package checksum
in that crate's `.cargo-checksum.json`, and every file named by that manifest is re-hashed.
Missing, extra, symlink, git, path, checksum-drifted, and unlisted-source inputs fail before
Cargo executes. First-party `build.rs` files remain forbidden. The policy separately names
all nine admitted vendored build scripts; the observed set must match that list exactly, and
each script must also be inside the lock/vendor graph and covered by its crate's file checksum
manifest.

Cargo runs with `--frozen --locked --offline` from the immutable source snapshot, using a
new private empty `CARGO_HOME`; it cannot resolve dependencies from an ambient Cargo cache.
The admitted `.cargo/config.toml` is byte-exact and can only replace crates.io with the
tracked `vendor` directory. Package manifests must declare an approved SPDX expression.
Declared package MSRVs may not exceed Rust 1.96.1; an absent upstream MSRV is retained as
`undeclared`, not silently inferred. Every admitted crate must retain at least one non-empty
top-level `LICENSE*`, `COPYING*`, or `COPYRIGHT*` file; those exact names travel in build
context, SBOM, provenance, and the human inventory.

Build-context schema 3 carries every Cargo purl, version, registry package checksum, license
expression, declared-or-undeclared MSRV status, build-script flag, and dependency edge.
CycloneDX emits 31 Cargo library components and the complete 43-edge transitive graph; the
Gateway application node points to its four exact direct dependencies. The same records are
included in provenance resolved dependencies. `docs/THIRD_PARTY_LICENSES.md` is the human
inventory, while the authoritative license texts remain checksum-bound inside each vendored
crate.

The resolution-only verification lane may validate the complete graph without compiling:

```bash
cargo_home="$(mktemp -d)"
trap 'rm -rf -- "$cargo_home"' EXIT
CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true \
  cargo metadata --manifest-path Cargo.toml --format-version 1 \
  --frozen --locked --offline
```

The temporary `CARGO_HOME` must be empty before invocation and removed afterward.

Tracked Cargo inputs without the two applicable policies, additional first-party manifests
or locks, non-canonical Cargo configuration, and lock drift fail before Cargo executes.
The standalone builder uses the same staged toolchain path and cannot silently emit a
Python-only artifact set when the Gateway policy is present:

```bash
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  python3 tools/reproducible_build.py --out dist --verify-reproducible
```

The public-tree leakage gate runs against a temporary materialization of the
same immutable `HEAD` objects used by the source archive. Clean filters or
other worktree transformations therefore cannot make forbidden committed
content disappear from the scan while leaving it in the artifact.
The admitted unit tests run from the same temporary immutable snapshot through
an isolated Python startup that imports the standard-library runner before
adding the snapshot import path. Clean-filtered worktree replacements and
repository `sitecustomize.py` or `unittest.py` shadows therefore cannot bypass
the test run under a receipt bound to different HEAD bytes.

Python is selected by exact version through a commit-pinned setup action, but
its interpreter and standard-library bytes are not yet reconciled to a content
digest. The policy, SBOM, and provenance therefore label it
`version_only_unverified`. This build is a reproducibility candidate, not a
content-pinned release receipt, until an external bootstrap verifies the Python
runtime closure.

## Dependency admission

`requirements-release.lock` is the only release-environment lock. It is empty
while the repository has no external runtime dependencies. Once a discovered
package declares one, the verifier refuses to build until the lock contains an
exact `name==version` requirement with at least one
`--hash=sha256:<digest>`. URLs, local paths, editable installs, mutable
versions, and unhashed entries are rejected. Build backends are not executed;
their requirements must still be exact pins so metadata cannot silently drift.

`requirements-release.graph.json` is the required dependency-edge companion
to the hash lock. It must contain exactly the same external package pins,
including transitives, and every edge must resolve to an exact locked version.
All locked nodes must be reachable from a distributable package. The SBOM
contains one component and one dependency-graph node for every entry, so a
flat direct-only graph cannot silently represent a transitive dependency as a
leaf. Optional and dynamic project dependencies are rejected until their
installation semantics can be represented without ambiguity.

Distributable projects use Core Metadata 2.4 and emit
`License-Expression: Apache-2.0` plus one `License-File` field for every
packaged license file. FaultLoom deliberately narrows PEP 639's more general
pattern language: `license-files` must be a non-empty list naming the direct
project-root files `LICENSE` and `NOTICE`. Empty lists,
absolute paths, traversal, globs, missing files, and case-folded duplicate
basenames fail closed. This stricter project policy ensures every public wheel
carries both policy files even though PEP 639 itself permits an empty list.
Paths must already be in canonical POSIX spelling: normalization never turns
`./`, repeated separators, trailing separators, or case variants into an
accepted declaration. Project readmes are likewise exact, glob-free files
directly beside `pyproject.toml`; nested and normalized aliases fail closed.

This graph is still operator-declared until an admitted wheelhouse supplies
independent package metadata. SBOM and provenance therefore label non-empty
graphs `declared_unverified`; structural reconciliation is not presented as
proof that an upstream transitive was not omitted. An empty external graph is
labelled `complete_no_external_dependencies`.

The lock currently declares expected hashes but there is no admitted offline
wheelhouse whose bytes are reconciled to them. SBOM and provenance therefore
label these values `declared_unverified`; they are never represented as
verified artifact digests. Release remains disabled until a wheelhouse or an
equivalent immutable dependency source is checked against every declared hash.

Package discovery is recursive beneath each configured package root so a
manifest cannot be silently omitted. The supported layout is exactly
`<package-root>/<package>/pyproject.toml`; root-level or deeper nested manifests
are rejected. Internal dependencies must pin the actual version of the
discovered package. Tracked symlinks and gitlinks are rejected rather than
followed into wheel or source-archive content. Project values interpolated
into wheel metadata headers must be strings without control characters, so a
multiline description cannot inject an undeclared dependency header.

The package metadata reader intentionally implements a narrow static subset:
numeric three-part versions, exact dependency pins, bounded Python-version
comparisons, an Apache-2.0 license string, and Markdown or reStructuredText
readmes. Dynamic metadata, entry points, scripts, optional dependencies, and
readme table forms fail closed. Generated wheels reserve installer-controlled
`.dist-info`, `.data`, `.egg*`, `.pth`, and interpreter-startup namespaces.
Shared/static-library and object-file names, plus ELF, PE, Mach-O, archive,
LLVM bitcode, and COFF payload bytes, are rejected so a `py3-none-any` wheel
cannot silently contain native code. Verification
requires one unique `RECORD` row per member and recomputes every recorded
SHA-256 digest and size.

Source and wheel member names are checked for cross-platform extraction safety.
They are ASCII-only, use components no longer than 255 characters, reject
Windows reserved names, alternate-data-stream syntax, trailing dots or spaces,
DOS 8.3 alias-shaped names, case-folded collisions, and file/directory
collisions, and enforce a conservative 4096-character total path bound. License
basenames are subject to the same portable flattening
constraints before they are copied into wheel metadata.

Reproducible SBOM and provenance metadata omit optional wall-clock creation/run
timestamps and invocation IDs. The Git commit time is a source-normalization
input, not the time at which the builder ran. Operational systems may bind real
invocation times in a separate signed receipt without making the reproducible
statement dishonest.

The developer snapshot in `requirements-dev.lock` is not consumed by release
or CI builds. A later test-environment admission task must replace that
snapshot with a platform-complete hashed lock before CI may install it.

## Release remains disabled

The public build policy has `release_enabled = false`. The builder can produce
reproducible release-candidate artifacts, but release mode fails closed. T41
may enable it only after the signed human authorization verifier, SBOM and
provenance gates, private evaluation receipt, and exact artifact digest checks
are integrated. It must also provide enforced network isolation and reconcile
all external lock hashes to an admitted offline wheelhouse. This repository
contains no publishing step or credential.
