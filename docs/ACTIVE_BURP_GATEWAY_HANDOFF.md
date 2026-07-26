# Active Burp Gateway handoff

`ActiveBurpGatewayHandoff` is a candidate-only adapter for one explicitly
selected Burp item. This G43 slice accepts only the owned `127.0.0.1` loopback
target. It has no HTTP client, socket, launcher, or request construction path.
It accepts a prepared `GatewayDispatchCommand` and invokes only the supplied
existing Gateway `dispatch(command)` surface. A focused runtime-negative test
replaces socket and standard HTTP-client connection primitives with fail
sentinels while it runs preparation, signed-authority/scope rejection, changed
command rejection, and the supplied-Gateway handoff; no sentinel is called.

Before that call, the handoff re-checks the immutable command digest and
verifies both independently signed artifacts:

- the authority grant, including target, pack, action, identity, execution
  window, and maximum budget; and
- the current scope epoch, bound to the same grant and lease epoch.

The Gateway command must still match the selected host, method, path, body,
budget, and identity. A returned receipt must bind back to that exact command.
Every failure occurs before the Gateway call.

The resulting `BurpGatewayCandidateReceipt` records that the Gateway completed
the action, but remains `candidate_only=true`, `verification_evidence=false`,
and `verification_status="unverified"`. It is not a finding, verification, or
authorization to contact any target outside the controller-provisioned Gateway
path. The focused owned-loopback test uses only `127.0.0.1` and a recording
Gateway test double; it makes no third-party connection.
