# T40 adapter admission materializer

`faultloom-materialize-adapter-admission` creates the fixed formal input as a staged source
artifact for the Ops bundle builder:

`<staging-root>/adapter-admission-bundle.json`

The materializer never writes `/etc/faultloom`. The Ops provisioner consumes the staged artifact
and performs the separate create-once installation at
`/etc/faultloom/t40-formal-v1/adapter-admission-bundle.json`.

The command is production root-only. It accepts producer and verifier Ed25519 raw32 seeds only
through already-open inherited file descriptors. It does not accept key paths, environment
variables, model callables, fixture evidence, target addresses, network settings, or submission
options. The two seeds must derive distinct protocol key IDs of the form
`ed25519:sha256:<public-key-sha256>`.

The input names the canonical root-owned mode `0400` Ops `staging-manifest.json` and its trusted
`staging_manifest_sha256`; callers do not supply a Core-wheel digest. The materializer verifies the
exact `faultloom.ops.t40-formal-staging.v1` contract: all six ordered source roles, generation and
site topology, the single mode `0400` Python launcher, its exact `/usr/bin/env -i` argv prefix,
fixed environment and isolation flags, and every
directory and file in the complete installed-tree inventory. It derives the Core-wheel digest from
the pinned manifest and binds the staging-manifest and installed-tree digests into both transcript
identities, the signed evaluation plan, and the output bundle. The producer `profile_digest`
remains the formal config-only digest used by the installed producer binding. Loaded Core,
Protocol, SDK, and Pydantic origins must be the corresponding files under that site; an ambient or
sibling checkout is rejected.

Before the sealed run, create a dedicated absolute root-owned, root-group, mode `0700` staging
directory. Install this canonical JSON inside it as root-owned, root-group, mode `0600` under
`adapter-admission-input.json`:

```json
{"bundle_id":"adapter-reference-admission-1","evaluator_challenge":"<64 lowercase hex with at least eight distinct bytes>","maximum_response_bytes":65536,"output":"adapter-admission-bundle.json","producer_state":"adapter-admission-producer.sequence","schema_version":"faultloom.adapter-admission-input.v1","session_id":"adapter-admission.session-1","staging_manifest_path":"/run/faultloom-t40-build/<generation-id>/staging-manifest.json","staging_manifest_sha256":"sha256:<trusted canonical manifest digest>","timeout_seconds":120,"verifier_state":"adapter-admission-verifier.sequence"}
```

Invoke the entry point with the two prepared descriptors:

```console
faultloom-materialize-adapter-admission --staging-root /run/faultloom-t40-build/adapter-admission --producer-key-fd 3 --verifier-key-fd 4
```

The command executes exactly one owned `.invalid`/loopback calibration case twice, baseline then
treatment. Treatment is the result of an actual `adapter.reference` normalization; baseline is the
same observation before normalization. Both calls use the fixed
`/opt/faultloom/model-utility-v1` profile with identical model, runtime, budget, generation config,
and seed. Prompt and tool-schema digests are deliberately distinct. The reference adapter is also
run for `describe` and `normalize` receipts.

Producer sequences and verifier/admission sequences are append-only and fsync-backed in the two
descriptor-relative state files. The bundle preserves exactly two signed producer sequence-proof
wrappers with allocation IDs `<bundle-id>.producer.1` and `<bundle-id>.producer.2`; each wrapper
binds the complete accepted nested producer attestation, its canonical payload digest, and an
Ed25519 signature. The output is canonical JSON, root-owned mode `0600`, and create-once. Any
existing output, unsafe metadata, symlink, race, timeout, response reuse, binding mismatch, or
verification failure exits nonzero and leaves no partial output.

The verifier key is first opened in a separate short-lived child launched through the verified Ops
`isolated-launcher`. That child independently re-reads and verifies the canonical manifest,
single launcher, full site tree, and import origins, then returns only its public key and the three
derived staging identities. The producer refuses any parent/child identity disagreement or equal
producer/verifier keys before adapter description, normalization, sequence allocation, or either
model call. Each sequential call has an independently verified transcript-evidence digest binding
its ordinal, arm, signed producer envelope and sequence proof, canonical request/response, staging
manifest, and installed tree.

The staged output carries `staging_manifest_sha256` and `installed_tree_sha256`. The installed arm
consumer recomputes their signed evaluator-plan binding and requires the actual bundle and staging
digests to equal the root-owned signed formal-install profile before accepting the admission proof.

`--dry-fixture-root` exists only for deterministic tests. Its subprocess model seam is explicitly
reported as `dry_fixture`; it never invokes the production API and must not be used as formal
evidence. Production has no fixture or callable injection parameter.
