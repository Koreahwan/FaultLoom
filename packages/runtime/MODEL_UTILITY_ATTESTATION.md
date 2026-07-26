# Transient model utility producer attestations

The producer attestor is a one-shot stdio process. It accepts exactly one
canonical JSON document followed by one LF, invokes the existing digest-pinned
local-model proxy once, emits one canonical response envelope followed by one
LF, and exits. It has no listener, socket, daemon mode, or persistent child.

The signing seed is an operator input inherited through a pre-opened file
descriptor. It is never accepted in the request, argv, or environment, and the
producer has no key-generation or trust-selection fallback. Runtime profile and
finite process limits are operator argv, while the model request remains the
single bounded stdin envelope.

The producer receipt binds the canonical request and parsed response, output,
model, standalone wrapper, runtime bundle, bubblewrap, fixed launch argv, Core
wheel, and runtime-profile digests. `raw_llama_stdout_digest` comes only from
the pinned wrapper's digest of the actual llama subprocess stdout. The attestor
does not mislabel or hash the wrapper JSON stdout as llama stdout. Wrapper JSON
must exactly equal the canonical reserialization of the parsed response.

Sequence state is a mode-0600 append-only journal outside `/opt`, anchored
through stable parent and state-file descriptors. After the initial `openat`,
state I/O uses only `pread`/`write` on that exact open file description; no
database library or pathname can reopen a swapped leaf. Cross-process `flock`
serializes allocation. Symlink, nonregular, hardlinked, wrong-owner,
wrong-mode, replaced-inode, corrupt, rolled-back, reused, and concurrent
duplicate state fails closed. Each allocation validates the named and opened
device/inode identities before and after the append and returns only after file
and parent-directory fsync.

Core does not implement an independent verifier signer. Core carries and
verifies the public producer/verifier attestation contracts; private cases,
oracles, and verdict derivation belong to the separate private Eval harness.
This package therefore does not sign caller-supplied outcome or safety claims.
