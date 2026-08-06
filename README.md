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

For a small supervised comparison, `campaign run-http1-triad` consumes a
strict local JSON spec and sends exactly three sequential signed-scope
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

For the direct sender, hostname-only external targets use `https`; plaintext
`http` requires an explicitly signed literal numeric IP or signed CIDR. An
explicitly signed local `127.0.0.1` target remains supported.

See [SECURITY.md](SECURITY.md) and [ETHICAL_USE.md](ETHICAL_USE.md) before use.

The practical authorized automation flow is documented in
[`docs/AUTHORIZED_AUTOMATION.md`](docs/AUTHORIZED_AUTOMATION.md). It covers
signed redacted evidence disclosure, provider-only reasoning, candidate
admission, the default personal direct sender, optional one-shot Gateway
dispatch, independent verification, and manual report outboxes. Live mode
remains off by default and no automatic submission is provided.

For an independent, read-only review of this public Core and its intended
personal workflow, see [GPT_PRO_REVIEW_PROMPT.md](GPT_PRO_REVIEW_PROMPT.md).

## Build verification

The clean-checkout build is offline and byte-reproducible. With the pinned
Python and Rust toolchains preinstalled, run:

```bash
python3 tools/verify_clean_checkout.py
```

See [docs/REPRODUCIBLE_BUILDS.md](docs/REPRODUCIBLE_BUILDS.md) for dependency
admission, artifact metadata, and the intentionally disabled release gate.
