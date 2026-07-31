# OpenAI-compatible model providers

`OpenAICompatibleProviderProxy` is a Chat Completions translation layer above
FaultLoom's existing `egress.ProviderProxy`. It does not open sockets or accept
an arbitrary URL at dispatch. Every call is compiled by the model-egress plane,
which rechecks signed authority and epoch state, destination resolution, replay
holds, provider/model/data policy, request and response byte ceilings, and a
no-redirect transport binding.

`OpenAICompatibleEgressTransport` is the `ProviderTransport` used by that
plane. Its production constructor always creates `PinnedHttpsGatewayPort`,
which opens TLS only to the
already compiled `resolved_addresses`; it preserves the compiled origin's Host
header and TLS SNI, uses the platform certificate verifier, bypasses proxy and
ambient DNS configuration, follows no redirects, and accepts only bounded
HTTP/1.1 `Content-Length` or chunked responses. The explicit
`for_testing` factory may accept a fake HTTP port, but a test-only transport
cannot attach to live egress or dispatch a live proxy request. The immutable
credential resolver, pinned port, and complete endpoint configuration are
content-addressed into `transport_id`; the descriptor is recomputed before each
dispatch. Live egress itself rejects a transport marked test-only before it
compiles or invokes a provider transport. The transport also retains and checks
the original resolver and HTTP-port object identities on every dispatch, so a
same-identity replacement cannot reach a credential-bearing call.

Endpoint configuration stores a validated HTTPS base URL, configurable relative
Chat Completions path (default `/chat/completions`), exact model ID, `SecretRef`,
and independently pinned `ProviderObservedMetadata`. It has no API key. A
credential resolver is injected into the trusted egress transport and is bound
to the compiled endpoint, provider, origin, resolution digest, destination
digest, and `SecretRef`; the optional `BoundEnvironmentCredentialResolver`
receives an explicit environment mapping and binding, so endpoint configuration
cannot select arbitrary ambient environment values.

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

Prompt payloads are digest/byte-bound before egress admission. Function calls
use `OpenAICompatibleFunctionSchema`: its source is exact canonical JSON bytes,
the source digest must equal the matching `ProviderToolSpec.input_schema_digest`,
and the tool ID and provider wire name are fields of that same spec. The
complete ordered-free tool contract must equal the request's
`tool_schema_digest` (which the adapter has already matched to the pinned
profile). The transport rejects missing, mismatched, or duplicate tool IDs and
function names before it serializes `tools` or `tool_choice: "auto"`. An empty
tool request still emits neither field, but its digest must equal the canonical
empty tool contract. The transport clones each admitted schema into an exact
canonical snapshot, and both its identity and the proxy contract bind the full
snapshot.

Schema admission supports only a bounded recursive subset: the exact JSON
types `object`, `array`, `string`, `integer`, `number`, `boolean`, and `null`,
with `properties`, `required`, and boolean `additionalProperties` for objects,
and `items` for arrays. Unsupported keywords, schemas deeper than 16 levels,
or schemas larger than 256 nodes are rejected before dispatch.

For a valid tool-enabled response, the proxy accepts at most 16 calls from the
first completion choice. Each call retains its provider ID, configured function
name, and exact JSON argument string in the signed `ProviderToolCall` result.
Arguments must be a duplicate-free JSON object no larger than 4096 UTF-8 bytes;
they are then recursively validated against the exact admitted schema before a
call can complete. Each signed call carries both the FaultLoom tool ID and the
provider wire name. Unknown names, missing or additional properties, type
mismatches, duplicate call IDs, malformed arguments, or an oversized call make
the observed response fail closed. Plain text and JSON-format requests do not
interpret incidental provider `tool_calls` extensions.

This proxy does not route or rank models. `ProviderAdapter` continues to bind
the pinned `ProviderModelProfile`, capability/metadata evidence, scope/policy
and data references, signed proxy attestation, and token/cost/byte budgets.
A subscription-only service needs an official API, OAuth, CLI, or SDK adapter
behind `ProviderProxyPort`; consumer cookies and browser sessions are not API
credentials and are not used.

## Offline manual handoff

`faultloom automation export-handoff` is outside this provider transport. It
renders the canonical bounded messages and one restricted function schema for
manual use with any model UI, CLI, or official API, but opens no provider
connection and supplies no endpoint, credential, or cookie. Its bundle is
explicitly `unattested_manual_handoff`; it neither verifies provider disclosure
nor claims provider/model attestation. The operator saves the returned single
function-arguments object and submits it to the separate offline
`faultloom automation compile` command, which remains candidate-only.
