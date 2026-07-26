# G45 owned Cloud/IAM/OAuth fixture

`manifest.g45.json` is a static Ed25519-signed, digest-pinned input manifest. It
enumerates four canonical JSON projections: two diagnostic candidates and two
matched negative controls. The file contains only a public key and detached
signature; no signing key, cloud identity, session, token, or provider endpoint
is included.

`LoopbackCloudTrustFixture` serves those exact projections only over owned
`127.0.0.1` GET routes. `evaluate_owned_cloud_trust_fixture` verifies the
manifest and source digest, then compiles an exact `GatewayDispatchCommand` for
the simulated `g45.fixture.invalid` endpoint. The command is an inert plan:
this fixture never launches a Gateway, dispatches it, or calls a provider API.

The resulting verifier receipt is deterministic and always `verified=false`.
It records either `candidate_only` or `matched_negative_control`; neither is a
claim about a real Cloud/IAM/OAuth environment. After context exit,
`cleanup_proof()` verifies that the loopback server is stopped, no dispatch or
provider call occurred, and the served inputs/manifest contain no secret-like
material.
