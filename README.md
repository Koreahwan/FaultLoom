# FaultLoom

FaultLoom is an authorization-first security research harness. A persistent
frontier Researcher may propose observations, experiments, and exploit-chain
hypotheses, but a deterministic Rust Gateway independently decides whether any
target action is in scope and issues the only usable dispatch leases.

The v0.1 Research Preview is designed for owned loopback labs and explicitly
authorized Web/API and LLM/agent assessments. Live mode is off by default.
FaultLoom does not promise automatic zero-day discovery or complete lab
coverage.

## Repository layout

- `packages/protocol`: versioned Pydantic and JSON Schema contracts
- `packages/sdk`: out-of-process pack and adapter SDK
- `packages/runtime`: CLI, durable state, Researcher, verification, reporting
- `packs/web`: identity/workflow and API/asynchronous surface pack
- `packs/llm`: LLM, RAG, MCP, and agent workflow pack
- `gateway`: Rust scope, lease, budget, and dispatch policy process
- `labs`: public loopback-only fixtures
- `tests`: cross-artifact contract and safety tests

None of the Python packs may open target sockets. Automated target dispatches
must be mediated by the Gateway; the personal CLI also has a separate,
owner-directed signed-scope `scope send-request` path for one bounded direct
HTTP/1.1 `GET`/`HEAD`/`OPTIONS` request. Installation of a pack never grants
authority.

The direct sender returns no response body preview by default. Its
`--body-preview-chars 0..3072` option is explicit opt-in only after a
non-sensitive response expectation and provider/model-processing permission;
the formal `doctor --json` `network_access` remains separate from the
`personal_direct_send_*` capability fields.

An offline automation result can be connected to this personal path with
`campaign prepare-http1-triad`. The command does not let model output author
request bytes. It binds one coordinator-admitted `observe`/`safe_probe`
candidate to an operator-authored v1 triad template, the verified workspace
and grant, the exact result/receipt, and both raw request digests. It produces
a review-required v2 spec without provider or target access. The run and
finalization commands revalidate those sources; changed provenance or request
bytes fail before a socket is opened.

For the archived-exchange path, `campaign supervise-model-http1-poc` takes an
archived exchange ID, its exact `AutomationRequest`, an external model-turn
file, strict operator-authored metadata, and a negative-control path. It
deterministically compiles offline exactly one safe-PoC step with zero generic
actions, keeps the archived effect bytes exact, and derives the control by
changing only the request target. The model cannot author raw requests or
finding prose. A private, create-once bundle is keyed by the source digests;
its provenance records the external authorization reference as
`operator_asserted_unverified` while binding the signed grant and run
separately. The supervisor then requires exact `RUN <campaign-id>` and
`FINALIZE <campaign-id>` acknowledgements around exactly three sequential,
no-retry sends (effect, the same effect as reproduction, and the derived
control), and resumes durably without replaying completed work. When
finalization succeeds with `finalStatus=draft_unverified`, it creates or
verifies the campaign-derived source handoff directly under the verified
workspace. The trust JSON names its content-addressed safe filename as
`campaign-<handoff-sha256>.verification-handoff.json`; consume its `handoff`
and `handoffSha256` fields rather than constructing a filename. The result also
includes the next reviewer action. A `review_required`, pending, negative, unresolved, or otherwise
non-`draft_unverified` result creates no handoff. It makes no provider,
Gateway, Burp, or submission call; independent verification and the manual
report path remain separate. The reviewer action still requires a separate
workspace, actor, signing key, and active authorization, plus its own exact
`RUN <campaign-id>` and `FINALIZE <campaign-id>` checkpoints.

For the same bound workflow with less command juggling,
`campaign supervise-http1-triad` prepares or resumes the campaign in one
interactive invocation. It requires the exact acknowledgements
`RUN <campaign-id>` before target traffic and `FINALIZE <campaign-id>` after
the operator privately reviews the three responses. Prompts use stderr and
stdout remains one JSON result. It never retries an unresolved or possibly
started campaign; a start-only crash is reported with dispatch state
`unknown` for manual reconciliation.

For a small supervised comparison, `campaign run-http1-triad` consumes a
strict local v1 or bound v2 JSON spec and sends exactly three sequential signed-scope
requests: one effect request, the same effect request again as reproduction,
and one minimally changed negative control. It has no preview, retry,
redirect, provider, Burp, evidence, or submission path. If any dispatch is
ambiguous it stops as `unresolved_no_retry`; it never guesses a completion.
After the operator reviews the private responses and confirms they are
non-sensitive, `campaign finalize-http1-triad` runs offline, archives the
three exchanges, and applies only the `exact_body_digest_v1` classifier. An
equal effect/reproduction body digest with a different control digest creates
an explicitly `draft_unverified` finding; every other outcome is a
`negative_campaign`. This is a bounded triad comparison, not independent
verification or proof of a vulnerability.

A completed bound-v2 `draft_unverified` campaign can also be exported with
`campaign export-verification-handoff` when using the phase commands directly.
The model-supervisor path performs the same source-side handoff creation and
verification automatically. In either case, the handoff is one private,
create-once direct child of the source workspace containing only relative
references, sizes, digests, and pending verification requirements. It includes
no raw bodies, secrets, verdict, report, target/provider traffic, or submission
authority.

For the direct sender, hostname-only external targets use `https`; plaintext
`http` requires an explicitly signed literal numeric IP or signed CIDR. An
explicitly signed local `127.0.0.1` target remains supported.

See [SECURITY.md](SECURITY.md) and [ETHICAL_USE.md](ETHICAL_USE.md) before use.

The practical authorized automation flow is documented in
[`docs/AUTHORIZED_AUTOMATION.md`](docs/AUTHORIZED_AUTOMATION.md). It covers
signed redacted evidence disclosure, provider-only reasoning, candidate
admission, the default personal direct sender, optional one-shot Gateway
dispatch, independent HTTP response-differential replay, and manual report
drafts. That replay reports only `observation_reproduced`; vulnerability
semantics and taxonomy remain `not_evaluated`. Live mode remains off by default
and no automatic submission is provided.

The class-specific read-only BOLA candidate commands are documented in
[`docs/BOLA_READ_CANDIDATE.md`](docs/BOLA_READ_CANDIDATE.md):
`prepare-bola-read`, `run-bola-read`, `export-bola-read-handoff`, and
`finalize-bola-read-review`. Source and reviewer workspaces each run an exact
three-`GET` control flow; the result is only an independently reproduced
cross-principal owner-object read, with BOLA policy, taxonomy, and impact left
`not_evaluated` for manual review.

For an independent, read-only review of this public Core and its intended
personal workflow, see [GPT_PRO_REVIEW_PROMPT.md](GPT_PRO_REVIEW_PROMPT.md).

## Build verification

The clean-checkout verifier requests offline package-manager behavior and
checks byte reproducibility; it is not a hermetic or network-isolated release
receipt. With the pinned Python and Rust toolchains preinstalled, run:

```bash
python3 tools/verify_clean_checkout.py
```

See [docs/REPRODUCIBLE_BUILDS.md](docs/REPRODUCIBLE_BUILDS.md) for dependency
admission, artifact metadata, and the intentionally disabled release gate.
