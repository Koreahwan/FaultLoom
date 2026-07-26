# Local model attestations

Core exposes digest-only wire contracts for two independent roles:

- `ModelProducerAttestation` records the provisioned producer identity, evaluator
  challenge, monotonic session sequence, exact request/response/output digests,
  pinned model and runtime artifacts, status, and token counts. It cannot carry
  verifier, safety, oracle, or independent-replay claims.
- `ModelVerifierAttestation` records a distinct verifier identity, artifact and
  profile, the producer envelope digest, opaque case/oracle/reset/replay evidence
  digests, and the verifier's derived outcome, safety, context-isolation, and
  independent-replay facts.

Each signed envelope carries `sha256(canonical_json(payload))`. Its Ed25519
signature covers canonical JSON containing both `payload` and `payload_digest`.
Canonical parsers reject alternate JSON encodings and unknown fields. Verification
requires caller-supplied trust registries; no public key embedded or selected by an
envelope establishes trust. Pair verification also rejects shared producer/verifier
identities, keys, profiles, or producer/verifier artifacts.

Private keys, prompts, model output, private cases, oracle contents, reset/replay
evidence, process launch details, and network behavior are intentionally outside
this public protocol package.
