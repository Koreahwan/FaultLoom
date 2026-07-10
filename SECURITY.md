# Security policy

FaultLoom v0.1 is a research preview. Do not use it as a security boundary for
systems outside an explicitly authorized engagement.

## Reporting a vulnerability

Do not include credentials, personal data, customer names, live target details,
or destructive proof in a public issue. Contact the maintainers privately with:

- the affected FaultLoom version and artifact SHA-256;
- the Gateway, protocol, pack, or runtime component involved;
- a minimal owned-loopback reproduction;
- the expected and observed scope decision; and
- whether target egress, cross-engagement retrieval, signature verification, or
  state-change cleanup could be bypassed.

Safety-kernel defects require a fail-closed kill switch and a forward fix. A
Gateway, authority-key, or scope-ledger format is never rolled back. Do not test
a suspected bypass against third-party infrastructure.

## Supported surface

Only the exact release-candidate digest named by a release receipt is supported.
Development branches and unapproved private builds are unsupported.

