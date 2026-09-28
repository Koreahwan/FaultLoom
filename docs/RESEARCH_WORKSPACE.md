# Research workspace preview

The source tree includes a reference catalogue and a private work notebook for
research, bug bounty, and client work. They preserve sources, decisions,
corrections, and file versions. These features are development source, separate
from the immutable personal RC20 package.

The notebook and catalogue add no research-target access or model calls. The
browser editor uses only an authenticated loopback listener. A notebook entry
is an operator's record; it does not attest a finding, payment, or vendor outcome.

## Try a synthetic example

Use an installed Python 3.12 runtime with `cryptography==41.0.7`, matching the
repository's existing runtime requirement. The demo installs nothing and makes
no network request. Choose a new absolute directory outside all Git worktrees:

```text
python tools/history_demo.py --out /absolute/private/faultloom-demo
```

On Windows, pass the absolute path of a local directory, such as
`C:\Private\faultloom-demo`. Do not use a network share. The destination must
not exist. A failed run retains its partial output for inspection.

The result contains three synthetic cases, fifteen events, three reference
documents, and three encrypted file copies. It also contains a verified backup,
a metadata catalogue, and a static viewer at `site/index.html`. All titles and
documents are invented for this example. Generated IDs, encryption, and times
vary; expected counts and byte preservation are the reproducible properties.

The static viewer can be opened locally. To try editing, use a Python runtime
whose `PYTHONPATH` includes `packages/runtime/src` and run:

```text
python -m faultloom.history_cli serve --directory /absolute/private/faultloom-demo/history \
  --session-file /absolute/private/faultloom-demo/editor.access \
  --catalog /absolute/private/faultloom-demo/catalog.json \
  --source-root /absolute/private/faultloom-demo/sources \
  --reference-root demo=/absolute/private/faultloom-demo/sources
```

The server prints a base URL and a private session-file path. Open the launch
URL from that file within five minutes; it is exchanged once for a local session.
Use a new session filename after restarting. On Windows,
`tools/history.ps1 -Python C:\path\to\python.exe serve ...` sets the import path
for the invocation. The generated keys, session files, and databases are runtime
data. Keep them outside the repository even when the example is synthetic.

For public screenshots, use only the example's static `site/` pages, which contain
synthetic records. Real history exports are decrypted private copies and need a
separate content review before sharing.

## Reproduce the checks

From this source checkout, with the repository's test dependencies installed:

```text
python -m pytest tests/runtime/test_knowledge_catalog.py tests/runtime/test_work_history.py tests/runtime/test_history_server.py tests/runtime/test_history_files.py tests/runtime/test_history_demo.py
```

The tests cover source binding, unchanged/changed/missing references, encrypted
records and attachments, preservation through corrections, transaction rollback,
duplicate writes, backup restoration, local-session checks, and UI route contracts.
HTTP tests contact only their disposable loopback notebook server. Windows skips
platform-specific symlink cases; inspect the test report for the exact count.
These are notebook checks, not a full FaultLoom release or research-performance
evaluation. No model needs to be installed or authenticated for them.

This preview was developed with AI coding assistance. Local automated checks
and browser inspection support the implementation claims; they do not replace
independent review or constitute a comparative model study.

## What to measure in future research

Record the input snapshot, method, model configuration when one is used, output,
reviewer decision, and uncertainty separately. A comparison should change one
factor at a time and report negative or inconclusive outcomes.

| Question | Controlled comparison | Evidence to retain |
| --- | --- | --- |
| Does missing context change a review? | Same synthetic brief, with and without its referenced configuration | Available inputs, supported conclusions, unsupported claims |
| Does reference retrieval help? | Same brief and time allowance, with and without a fixed reference selection | Retrieved source IDs, hashes, relevant citations, review time |
| Is the tool the operational bottleneck? | Same notebook task with manual files and the workspace | Completion, reconstruction errors, setup time, correction and recovery behavior |
| Does a model choice help? | Same frozen input, rubric, tool access, and budget across selected models | Raw bounded outputs, blind review where feasible, elapsed time, measured usage, missing-context and refusal labels |

Do not infer practical discovery rates from tool unit tests, model response
rates, or offline source-review scores. A dataset's license and disclosure
status must be checked before publishing it. This preview supplies the record
and provenance layer; it reports no comparative model result or new finding.

## Source and publication boundaries

The implementation is maintained in the public Core source tree. The local
catalogue can point to preserved references without copying their bodies into
Git. Historical imports retain their original dates and statuses, and are kept
separate from new FaultLoom work. The code's presence under the project license
does not grant permission to redistribute referenced third-party documents.

A public change should contain selected source, tests, documentation, and
synthetic examples. Exclude personal records, imported history, source corpora,
customer documents, archives, private keys, `.access` files, and local outputs.
An automated secret scan supports this review but cannot establish disclosure
permission or prove all private information absent. A local review bundle is
not a publication receipt.

See [reference catalogue](REFERENCE_WORKSPACE.md) and
[private work history](WORK_HISTORY.md) for limits, command contracts, and the
local key and backup model.
