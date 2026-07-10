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

None of the Python packs may open target sockets. All target dispatches must be
mediated by the Gateway. Installation of a pack never grants authority.

See [SECURITY.md](SECURITY.md) and [ETHICAL_USE.md](ETHICAL_USE.md) before use.

