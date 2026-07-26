# Offline model-utility v1 profile

The Core runtime admits one local profile at
`/opt/faultloom/model-utility-v1`. The provisioner performs no download. It
accepts only locally staged files, verifies the fixed bytes, and publishes the
profile with one atomic rename. Do not run it until the staged inputs and this
change have been reviewed.

Pinned inputs:

- `/usr/bin/bwrap`: SHA-256
  `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712`.
- `llama-b10107-bin-ubuntu-x64.tar.gz`: release `b10107`, commit
  `c0bc8591e8815c63cb01dd3f051a8b0df02501c9`, 16,275,561 bytes, SHA-256
  `afe1ae0b706c4a0830b218a9249037b7a6cc723f81deb78825662128b25453e6`.
- `smollm2-360m-instruct-q8_0.gguf` from revision
  `593b5a2e04c8f3e4ee880263f93e0bd2901ad47f` of
  `HuggingFaceTB/SmolLM2-360M-Instruct-GGUF`: 386,404,992 bytes, SHA-256
  `48ab3034d0dd401fbc721eb1df3217902fee7dab9078992d66431f09b7750201`.
- The executable runtime is the exact checked-in
  `model_utility_runtime_wrapper.py`; its digest is recorded in
  `model_utility_proxy_models.py` and rechecked by the provisioner.

The staged model metadata must identify the repository, revision, filename,
size, and digest above. The staged bundle metadata must identify the archive,
release, commit, size, and digest above. The exact 1,847-byte staged model card
is preserved as `MODEL_CARD.md`; it states that the GGUF was converted via
GGUF-my-repo and must not be rewritten as a first-party conversion claim. The
llama.cpp license is verified and copied from the pinned archive.

The wrapper extracts the complete dynamic bundle only inside the private
bubblewrap `/tmp`, rejects unsafe tar members, and invokes `llama-cli` with a
fixed CPU-only, offline, single-turn argv. The request still binds
`runtime_artifact_digest` to the standalone wrapper for compatibility; the
profile separately pins and records the full runtime-bundle digest.
