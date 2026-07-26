# External-domain ABI v1

`faultloom-sdk` accepts external-domain declarations as immutable data only.
It does not discover, import, execute, or download a pack from the declaration.
Target traffic remains exclusively a Gateway concern.

## Compatibility and rollback

The only accepted declaration vocabulary is ABI `1.0.0`. The model forbids
unknown fields, so even `1.0.1` is rejected until a corresponding model and
explicit compatibility rule are published. A caller admitting untrusted input
must use `ExternalDomainRegistry.admit_signed`, which verifies a signed
`AuthorityGrant` and enforces `minimum_grant_version`; a lower grant version is
rejected as rollback before any manifest is admitted. It returns an immutable
`VerifiedExternalDomainAdmission` capability only after the pinned verifier
key, signature, and canonical grant digest agree.

## Required bindings

The declaration binds one schema namespace, a canonical `PackManifest` digest,
and canonical adapter-manifest digests. Its declared capabilities and actions
must exactly cover those manifests. The pack's required Gateway features and
adapter capabilities are checked against host catalogs. External adapters may
use only `gateway_only` egress. Cleanup must be `receipt_required`, evidence
must be `digest_references_only`, and authority must name the pack, adapters,
and requested action families.

`canonical_external_domain_manifest_digest` hashes the strict canonical
declaration bytes. The conformance receipt records that digest together with
the `signed_authority_grant_digest` produced after signature verification. It
does not claim the declaration itself has a separate signature envelope.

## Reference fixture and receipt

`tests/sdk/fixtures/external_domain_v1_declaration.json` is the data-only v1
reference fixture. It has no executable entry point, network URL, credential,
target, or raw evidence field. The deterministic receipt accepts only the
immutable `VerifiedExternalDomainAdmission` returned by `admit_signed`; an
unsigned `admit` result is candidate/admission-only and cannot produce a
signed receipt. Receipt construction also requires the consumer's pinned
`trusted_public_key` and revalidates the retained signed grant envelope at the
consumption boundary; a private-helper object, forged signature, or different
key pin is rejected. The receipt contains only ABI, namespace, and digest bindings.
Serialize it with
`canonical_external_domain_conformance_receipt` for a byte-stable JSON
artifact.

Run the focused conformance scenario and write its JUnit receipt with:

```text
PYTHONPATH=packages/protocol/src:packages/sdk/src python3 -m pytest -q \
  -p no:cacheprovider \
  --junitxml=.omo/evidence/g47-external-domain-abi/pytest.xml \
  tests/sdk/test_external_domain_abi.py
```
