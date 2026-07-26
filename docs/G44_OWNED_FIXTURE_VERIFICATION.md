# G44 owned Web/API to LLM/MCP to Web3 fixture

This candidate gate is entirely in memory. It opens no socket, performs no RPC,
loads no wallet, moves no asset, and accepts only distinct `synthetic.*`
identities. Its final effect is the inert string canary
`effect.web3.g44-inert-zero-value-canary`.

The fixture emits JSON; `tools/verify_g44_fixture.py` consumes only that JSON and
does not import or invoke the lab. The verifier independently recomputes the
content-derived semantic signatures and edge IDs, finds the shortest
dependency-valid witness with a lexicographic tie break, and rejects a removable
edge. It also checks the pinned Web/API -> LLM/MCP -> Web3 boundary order,
separate Core/G42/pack artifact digests, four budgets, per-edge leases or
explicit no-dispatch receipts, both exact bridge-removal controls, pristine
clean replay, byte-for-byte reset ID preservation, cleanup, `lost_ids=0`, and
`duplicate_effects=0`.

The three artifact digests are not trusted as unsigned strings. A canonical
artifact-provenance manifest binds each exact relative path and SHA-256, the
G42/G44 goal IDs, candidate versions, primary run ID, and creation/expiry times.
It is signed with Ed25519. Verification requires a separately supplied pinned
public key and verification time; neither a public key embedded in evidence nor
any private/test key is accepted by the production verifier.

Generate evidence while pinning the actual local files selected for this run:

```bash
openssl genpkey -algorithm Ed25519 -out /tmp/g44-provenance-private.pem
python tools/build_g44_fixture_evidence.py \
  --core-artifact packages/protocol/src/faultloom_protocol/models.py \
  --g42-artifact packages/runtime/src/faultloom/semantic_depth.py \
  --pack-adapter-artifact packs/web3/src/faultloom_web3/fixture.py \
  --provenance-private-key /tmp/g44-provenance-private.pem \
  --provenance-public-key-output .omo/evidence/g44/provenance-public.pem \
  --created-at 2026-07-26T00:00:00Z \
  --expires-at 2026-07-27T00:00:00Z \
  --output .omo/evidence/g44/fixture-evidence.json
rm /tmp/g44-provenance-private.pem
```

Verify that saved data in a separate process:

```bash
python tools/verify_g44_fixture.py \
  .omo/evidence/g44/fixture-evidence.json \
  --trusted-provenance-public-key .omo/evidence/g44/provenance-public.pem \
  --verification-time 2026-07-26T12:00:00Z \
  --report .omo/evidence/g44/verification-report.json
```

A successful report is a candidate G44 fixture result only. It does not advance
the formal Ops ledger, complete T44/G44, authorize a live target, or affect v0.1.
Signed provenance proves fixture-to-artifact binding; it does not grant or prove
production authority, scope, target ownership, live enablement, or release approval.
