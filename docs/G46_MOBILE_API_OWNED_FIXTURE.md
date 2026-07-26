# G46 owned Mobile/API fixture

This candidate slice is a deterministic, fully simulated fixture. It extends
the supplied app-link/API JSON comparison but does not connect to a device,
invoke a Gateway, or call an external API.

`faultloom_mobile.g46_fixture` pins the fixture manifest to
`sha256:8ff668797785650b37df19c014aee653a8bc1c271686df721ec4fbc6b32753cd`.
It defines only synthetic device, application, and API identities. An external
authority supplies the Ed25519 public key plus a signature over the documented
canonical authority/scope/budget bytes. Production code verifies that signature
and mints an immutable admission token; only that token can create a command or
receipt. Test code generates ephemeral private keys for owned synthetic runs.
No hardcoded or shared signing secret exists in the production module, and an
external authority remains a separate requirement.

For a mismatched supplied observation, the fixture prepares exactly one
declarative Gateway command. That command is marked `inert_preparation_only`,
has `dispatched=False`, targets only `fixture://owned-g46-mobile-api`, and has
no execution method. The deterministic verifier receipt records only that
fixture invariants passed; it remains `candidate_only` with
`security_verified=False`.

The matched negative control requires the app-link URI, application/API
identities, and API audience to agree. It prepares no command. `reset()` and
`cleanup()` restore the initial state after every run, and the fixture rejects
credential-shaped artifacts.

Run the focused fixture contract:

```bash
pytest tests/mobile/test_api_binding_observation.py tests/mobile/test_owned_g46_fixture.py
```
