# OpenAI-compatible model providers

`OpenAICompatibleProviderProxy` is a Chat Completions translation layer above
FaultLoom's existing `egress.ProviderProxy`. It does not open sockets or accept
an arbitrary URL at dispatch. Every call is compiled by the model-egress plane,
which rechecks signed authority and epoch state, destination resolution, replay
holds, provider/model/data policy, request and response byte ceilings, and a
no-redirect transport binding.

`OpenAICompatibleEgressTransport` is the injected `ProviderTransport` used by
that plane. Its injected `OpenAICompatibleHttpPort` must honor the compiled
origin, resolved addresses, destination and dispatch-authorization digests,
and response-byte ceiling. This keeps concrete HTTP/TLS/Gateway mechanics out
of the high-level provider adapter.

Endpoint configuration stores a validated HTTPS base URL, configurable relative
Chat Completions path (default `/chat/completions`), exact model ID, `SecretRef`,
and independently pinned `ProviderObservedMetadata`. It has no API key. A
credential resolver is injected into the trusted egress transport and is bound
to the compiled endpoint, provider, origin, destination, and `SecretRef`; the
optional `BoundEnvironmentCredentialResolver` receives an explicit environment
mapping and binding, so endpoint configuration cannot select arbitrary ambient
environment values.

| Preset | Base URL |
| --- | --- |
| `KIMI` | `https://api.moonshot.ai/v1` |
| `GLM` | `https://open.bigmodel.cn/api/paas/v4` |
| `GROK` | `https://api.x.ai/v1` |

Presets only supply provider and URL defaults. An unknown future provider needs
only its validated base URL, exact pinned model ID, pinned metadata, secret
reference, and an official compatible transport; no core source change or
preset is required. The configured metadata is compared against the request
and returned as observed metadata—it is never copied from a request and marked
exact.

The existing provider port contains prompt/tool/config digests, not raw tool
schema bytes. Prompt payloads are digest/byte-bound before egress admission;
tool-enabled calls remain fail-closed until an attested schema-byte source is
added. Raw Chat Completions tool-call or reasoning fields remain in the bounded
response artifact represented by the signed response digest.

This proxy does not route or rank models. `ProviderAdapter` continues to bind
the pinned `ProviderModelProfile`, capability/metadata evidence, scope/policy
and data references, signed proxy attestation, and token/cost/byte budgets.
A subscription-only service needs an official API, OAuth, CLI, or SDK adapter
behind `ProviderProxyPort`; consumer cookies and browser sessions are not API
credentials and are not used.
