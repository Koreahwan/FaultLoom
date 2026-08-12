# BOLA read candidate

This is a bounded, authenticated, read-only candidate workflow for an owned or
explicitly authorized target. It is not a crawler, an exploit engine, or proof
of BOLA/IDOR.

## Workflow

The source and reviewer each use a different workspace, operator actor, signed
grant, signing key, requester auth-session ID, and target-bearer `SecretRef`.
The reviewer also uses a distinct source handoff and must not reuse the source
workspace, grant, actor, key, session, or `SecretRef`. Bearer values are
resolved only at run time and are never written to the case, handoff, result,
stdout, or other evidence artifacts.

1. `prepare-bola-read --phase source` signs a case that binds the target,
   tenant, object ID/kind and exact paths, owner and requester identities,
   stable response fields, the operator-reviewed owner binding, the expected
   denied cross-principal read, and the requester session `SecretRef`.
2. `run-bola-read` sends exactly three serial `GET` requests for that case:

   1. requester-authenticated `principal_control_path` (the principal control);
   2. the same requester session to `object_read_path` (the owner object read);
   3. an anonymous request to `object_read_path` (the non-public control).

   The first two must be successful. The anonymous control must be denied
   (`401`, `403`, or `404`) and must not expose the object. A dropped,
   ambiguous, or failed dispatch records `unresolved_not_evaluated`; it is
   never retried or replayed automatically.

3. `export-bola-read-handoff` validates the complete source triad and writes a
   signed, digest-bound handoff for the independent reviewer.
4. `prepare-bola-read --phase reviewer` consumes that handoff, recreates the
   same case relation in the reviewer workspace, and checks the independent
   boundaries. Run it with `run-bola-read` to collect the reviewer’s own three
   GETs.
5. `finalize-bola-read-review` verifies both signed triads and their local raw
   responses, then writes the local result. It performs no target, provider,
   Gateway, Burp, or submission call.

The command shape is:

```text
faultloom campaign prepare-bola-read --phase source ... --out <source-case.json>
faultloom campaign run-bola-read --workspace <source-workspace> --trusted-key <source-public-key> --private-key <source-private-key> --case <source-case.json>
faultloom campaign export-bola-read-handoff --workspace <source-workspace> --trusted-key <source-public-key> --private-key <source-private-key> --case <source-case.json> --run-result <source-run.json> --out <handoff.json>
faultloom campaign prepare-bola-read --phase reviewer ... --source-workspace <source-workspace> --source-trusted-key <source-public-key> --source-handoff <handoff.json> --out <reviewer-case.json>
faultloom campaign run-bola-read --workspace <reviewer-workspace> --trusted-key <reviewer-public-key> --private-key <reviewer-private-key> --case <reviewer-case.json>
faultloom campaign finalize-bola-read-review --source-workspace <source-workspace> --source-trusted-key <source-public-key> --reviewer-workspace <reviewer-workspace> --reviewer-trusted-key <reviewer-public-key> --handoff <handoff.json> --reviewer-case <reviewer-case.json> --reviewer-run <reviewer-run.json> --out <result.json>
```

The omitted `prepare-bola-read` fields are operator-authored target, object,
identity, path, session-expiry, response-limit, and confirmation options. Use
generic values for an owned loopback fixture; do not put live credentials or
personal data in examples or artifacts.

## Wire and result boundary

Requests are a strict HTTP/1.1 JSON subset: `GET`, one exact path, `Host`, an
optional `Authorization: Bearer ...`, `Accept: application/json`, and
`Connection: close`. Responses must have one HTTP/1.1 status line, exactly
`Content-Type: application/json`, `Content-Length`, and `Connection: close`
headers, a bounded body whose length matches `Content-Length`, and one JSON
object with no duplicate keys. Redirects, retries, alternate methods, and
ambiguous framing are outside this contract.

When both independent triads agree, the result may say only
`cross_principal_owner_object_read_reproduced`. The candidate class (`bola_idor`),
source claim, owner binding, requester-principal binding, and denied-read
expectation remain operator-asserted or observed—not target policy proof. The
candidate and source-policy claims remain unverified; the target authorization
policy is not evaluated.
`semantic_verdict`, `taxonomy_verdict`, and `impact_verdict` remain
`not_evaluated`; `report_status` is `draft_manual_review` and
`automatic_submission` is `false`. Human review is required, and this result
does not prove BOLA/IDOR.
