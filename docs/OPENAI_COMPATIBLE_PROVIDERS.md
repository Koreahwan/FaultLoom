# OpenAI-compatible model providers

`OpenAICompatibleProviderProxy` implements the existing signed
`ProviderProxyPort` using standard-library HTTPS and the Chat Completions path
`/chat/completions`. It makes no network call while being configured and it
never serializes an API key: an endpoint config contains a `SecretRef` plus the
name of an environment variable, and resolves the key only immediately before
dispatch.

Use `openai_compatible_preset` for a named endpoint and provide the exact model
ID that is pinned in the corresponding `ProviderModelProfile`; presets do not
pick a model for you:

| Preset | Base URL | Credential environment variable |
| --- | --- | --- |
| `KIMI` | `https://api.moonshot.ai/v1` | `MOONSHOT_API_KEY` |
| `GLM` | `https://open.bigmodel.cn/api/paas/v4` | `BIGMODEL_API_KEY` |
| `GROK` | `https://api.x.ai/v1` | `XAI_API_KEY` |

The generic configuration also supports another HTTPS OpenAI-compatible base
URL. Plain HTTP is accepted only for loopback test servers.

For an unknown future provider, configure its validated base URL, exact pinned
model ID, `SecretRef`, and credential environment-variable name; no preset or
core source change is needed when it implements this API shape. A service that
is available only through a subscription needs its official API, OAuth, CLI, or
SDK adapter behind `ProviderProxyPort`. This generic HTTP transport cannot—and
does not attempt to—turn a consumer subscription, browser session, or cookie
into an API credential.

This proxy selects neither a profile nor a fallback model. The exact configured
model must match `ProviderProxyRequest.model_snapshot`; otherwise it signs a
no-dispatch denial. `ProviderAdapter` continues to bind the pinned
`ProviderModelProfile` (capability and metadata evidence), scope/policy/data
references, signed proxy attestation, and token/cost/byte budgets. Ranking or
automatic model routing is deliberately outside this adapter.

The existing provider port carries a prompt digest/byte count, generation
config digest, tool IDs, and tool-schema digest—not prompt bytes or tool schema
bytes. Supply a local `OpenAICompatibleChatPayload` resolver and bind its
`prompt_digest()`, `prompt_bytes()`, and generation digest to the request. A
mismatch is denied before sending. Tool-enabled calls are also denied until the
provider contract has an attested source for tool schema bytes.

On a successful response the proxy signs its raw-response SHA-256 digest,
usage, status, byte counts, configured model identity, and all pre-existing
request/config/policy digests. Raw Chat Completions fields such as `tool_calls`
or provider reasoning fields remain inside the response artifact represented by
that digest; this port does not reinterpret or expose them. HTTP/provider
errors produce an attested failed result, while connection ambiguity produces
the existing reconciliation-required unknown outcome.
