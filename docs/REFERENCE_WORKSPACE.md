# Local reference workspace

The development-source CLI can catalogue explicitly selected reference files,
search their metadata, check current file hashes, and prepare a citation list
for human review. A standalone HTML overview provides search, type filters,
source details, and a selected-reference Markdown download.

This is a source-only addition. Existing immutable personal packages are not
rebuilt and their capability claims are unchanged. This module does not call a
model, contact a target, execute a reference, or submit a report. It does not
evaluate whether a source is correct, current, or suitable for a particular
engagement.

## Run from the source checkout

With an installed development runtime, use `faultloom knowledge --help`.
On Windows, the standalone path needs only an already-installed Python 3.12:

```powershell
.\tools\knowledge.ps1 --help
```

The PowerShell wrapper does not install dependencies or change saved settings.
Pass `-Python C:\path\to\python.exe` when the Python launcher is unavailable.
On other hosts, put `packages/runtime/src` on `PYTHONPATH` and run
`python3 -m faultloom.knowledge_cli`.

## Select sources explicitly

Create a UTF-8 selection file outside the preserved source directory:

```json
{
  "schema": "faultloom.reference-selection.v1",
  "origin": {"id": "personal-references", "label": "Personal reference archive"},
  "entries": [
    {
      "path": "templates/summary.md",
      "kind": "report_template",
      "title": "Customer summary template",
      "tags": ["report", "customer"],
      "review": "unreviewed"
    }
  ]
}
```

Paths are relative to an explicit absolute source root. A selection may also
bind `expected_sha256` to reject changes since an earlier inventory. Each
origin/path receives a stable reference ID; file hashes identify its content.
The catalogue contains metadata, not source bodies or an absolute source root.

Kinds are `reference`, `report_template`, `role_prompt`, `workflow_rule`,
`skill`, `research_note`, `case_record`, and `guide`. Optional review labels are
`unreviewed`, `operator_reviewed`, and `retired`. An operator review label is an
input annotation, not independent verification, scope permission, a finding,
or a publication decision. Public examples do not become personal achievements.

```powershell
.\tools\knowledge.ps1 build --source-root C:\ReferenceArchive `
  --selection C:\Work\selection.json --out C:\Work\catalog.json
.\tools\knowledge.ps1 search --catalog C:\Work\catalog.json customer --kind report_template
.\tools\knowledge.ps1 check --catalog C:\Work\catalog.json --source-root C:\ReferenceArchive
.\tools\knowledge.ps1 view --catalog C:\Work\catalog.json `
  --source-root C:\ReferenceArchive --out C:\Work\overview.html
```

Search matches all space-separated query terms against titles, paths, tags,
and category labels. It is deterministic metadata search, not body search or
semantic retrieval. Review status, source integrity, and content correctness
are separate fields.

## Prepare a review list

Use IDs returned by `search`; repeat `--id` to select several references:

```text
faultloom knowledge packet --catalog /work/catalog.json --source-root /references \
  --id ref_ID_FROM_SEARCH --purpose "Review report structure" --out /work/references.md
```

The CLI checks every selected source immediately before preparing the list.
Missing, changed, unsafe, or retired references prevent publication of that
output. The resulting Markdown contains purpose, source paths, reference IDs,
hashes, the check time, and pending content-review items. It includes no source
body or command execution instruction.

The HTML overview is an offline snapshot. Its Markdown download records the
snapshot check time and does not reread source files. Use the CLI for a fresh
source check. The UI does not modify catalogue review labels or remember
selection across reloads. This initial version has no case database or live
work history editor.

## File and rendering boundaries

- Outputs are create-only and must be outside the selected source root.
  Existing outputs are preserved; choose a new output filename for a revision.
- Only explicit text-reference paths are admitted. Parent traversal,
  noncanonical paths, Windows device names, links/reparse points, UNC paths,
  Windows remote drives, and common secret/configuration filenames are rejected.
- Read-only hard links are supported without breaking or changing the source.
- Inputs are bounded: 4 MiB JSON, 2,000 entries, 2 MiB per source, and 64 MiB
  total captured source bytes. Source bodies are read to hash them, not stored
  in the catalogue or HTML.
- File identity and metadata are checked around capture. Windows path/handle
  timestamp differences are handled without treating unchanged files as edited.
  This is not an OS-enforced sandbox against a hostile local filesystem owner.
- A catalogue digest detects accidental inconsistency, not a trusted signature.
  Review annotations and metadata remain operator-provided, untrusted data.
- The generated HTML uses text nodes for metadata, escapes embedded JSON, has
  a restrictive CSP, and loads no external scripts, fonts, images, or data.
  Treat generated catalogues and pages as private until their metadata is reviewed.

Exit codes: `0` completed; `2` invalid input or failed export; `3` a source
check completed and found a change, missing file, or unavailable reference.

## Existing runtime integration

The catalogue is a reference bibliography, separate from engagement-scoped
encrypted observations and event-bound search in StateStore. It does not
silently import those observations, create fake event provenance, or feed
archived role prompts to a model. Existing context/retrieval and verification
contracts remain unchanged.

Focused tests are in `tests/runtime/test_knowledge_catalog.py` and cover
source preservation, stale-reference rejection, portable path boundaries,
malformed inputs, output isolation, HTML escaping, and CLI integration.
