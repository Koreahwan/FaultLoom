# Private work history

The development-source `faultloom history` command records personal work in
three tracks: research, bug bounty, and client work. It is a local notebook and
historical record, separate from signed execution, verification, and submission
authority. It adds no target access, scanner, model call, or external messaging.
The existing immutable RC20 package is unchanged.

## Storage and provenance

Initialize a **new absolute directory outside Git worktrees**. All event
payloads, including titles, customer names, notes, and source paths, are AES-GCM
encrypted in SQLite. A generated local key is kept in `history.key`; the marker
and database identity bind the files together. Each writer uses a transaction.
An authenticated head seal and a digest chain detect modified, missing, or
reordered events when the rest of the current vault remains intact. An old
complete database backup, including its older valid head seal, cannot be
distinguished from intentional rollback without an external checkpoint.

The key file relies on local filesystem permissions. A copy containing both
the database and key is readable by its holder; it is not a password-encrypted
backup. No password, system credential, provider token, or existing target key
is reused. `backup` creates a new private directory containing all three files,
then independently opens it and compares the head and record count.

This is an operator notebook. Recorded submissions, delivery notes, outcomes,
severity labels, and historical bounty text are not independently verified
facts. The UI counts work items and records, not accepted vulnerabilities or
money earned. A correction is a new same-case event pointing to its predecessor;
the original remains visible. Occurrence time can be a date, a zoned timestamp,
or unknown. Recording time is stored separately.

## Commands

Use an installed Python 3.12 runtime with the project's existing `cryptography`
dependency. No new dependency is added. The source-only Windows launcher
`tools/history.ps1 -Python C:\path\to\python.exe ...` sets its import path for
the invocation and restores environment variables. It installs nothing.

```text
faultloom history init --directory /private/history
faultloom history create --directory /private/history --input /private/new-case.json
faultloom history record --directory /private/history --case case_ID --input /private/note.json
faultloom history update --directory /private/history --case case_ID --input /private/update.json
faultloom history list --directory /private/history --track client
faultloom history show --directory /private/history --case case_ID
faultloom history verify --directory /private/history
faultloom history backup --directory /private/history --out /private/backups/new-copy
```

Create input:

```json
{
  "title": "Example review",
  "track": "client",
  "domains": ["web_api", "ai"],
  "subject": "Operator-provided engagement label",
  "state": "active",
  "occurred_at": "2026-09-28"
}
```

The CLI fixes new work's origin to `faultloom`. Domains are `web_api`, `web3`,
`ai`, `other`, or `unknown`; unknown is used alone. States are `planned`,
`active`, `waiting`, `closed`, and `historical`. Updates may change title,
track, domains, subject, and state, preserving the previous event and origin.
A concurrent update causes a clear conflict instead of overwriting newer work.

Note input:

```json
{
  "kind": "decision",
  "summary": "Review remains incomplete",
  "detail": "Explain the evidence and authorship of this note.",
  "occurred_at": "2026-09-28T10:00:00+09:00"
}
```

Kinds are `note`, `decision`, `observation`, `negative_result`, `report`,
`submission`, `delivery`, `outcome`, and `correction`. A correction additionally
requires `corrects`, the ID of an earlier event in the same case. Notes are
supplied through a UTF-8 JSON file rather than exposed in command arguments.

`link` hashes one explicit reference text file without copying its body:

```text
faultloom history link --directory /private/history --case case_ID \
  --source-root /preserved/sources --path reports/result.md \
  --origin archive --label "Original report"
```

The reference's source-relative path and digest describe what was linked then;
they do not establish that the file is still available or correct today.
`link-file` supports document, image, source-code, video, and archive files up
to 16 MiB. It also records metadata only. Neither command executes or renders
the source body. `archive` separately preserves an encrypted byte-for-byte copy.

## Attachment archival and source checks

```text
faultloom history link-file --directory /private/history --case case_ID \
  --source-root /preserved/sources --path reports/result.pdf --origin archive --label "Report"
faultloom history archive --directory /private/history --case case_ID \
  --source-root /preserved/sources --path reports/result.pdf --origin archive --label "Report" \
  --expected-sha256 DIGEST_FROM_LINK
faultloom history extract --directory /private/history --case case_ID \
  --event evt_ATTACHMENT_ID --out /private/restored/result.pdf
faultloom history check-sources --directory /private/history --case case_ID \
  --reference-root archive=/preserved/sources --record
```

An attachment and its event commit in one SQLite transaction. The separate
attachment table holds AES-GCM ciphertext; associated data binds the vault,
case, opaque blob ID, content hash, and byte count. Original filenames and paths
remain encrypted in the event. Identical content reuses a blob within one case;
different cases receive distinct blobs. An existing archive can be downloaded
after the original changes or disappears. A new archive requires the original
to match the supplied digest. Extraction is create-only outside Git worktrees.

`verify` now authenticates every referenced blob and checks its bytes and hash.
`backup` copies the entire database, including attachments, then verifies the
copied records and attachment contents independently. Corrupt, missing, or
unreferenced blob data prevents a successful verification result. Failed
backups are retained for review, with the original unchanged.

Source checking returns `unchanged`, `changed`, `missing`, `unmapped`,
`unsafe_or_unavailable`, or `budget_exhausted`. It uses explicit origin/root
mappings and records source-relative paths, expected/observed hashes, and check
time. No request is sent to a research target. Use `--record` for an append-only
receipt; earlier source states remain. A missing mapping is not a missing file.
The checker counts references, which can point to the same physical file.

Limits are 16 MiB per file, 256 MiB total encrypted attachments, 1,024 blobs,
and 64 MiB captured source bytes per check. One check covers up to 200 recorded
references, subject to the normal event size limit when saving a receipt.
Credential/configuration names, traversal, symbolic links/reparse points, network paths,
and the history storage's own files are rejected. This is not a content DLP
scanner: selected document bodies may contain private information and remain
private. Archives are opaque; no archive extraction, document parser, or code
execution is invoked.

The new reader can open earlier history databases and backups without an
attachment table. Older source versions cannot interpret the new event kinds;
restart existing editor processes before adding these records. The immutable
RC20 package remains unchanged and does not contain this notebook feature.

## Historical Terminator metadata

```text
faultloom history preview-legacy --source-root /preserved/terminator
faultloom history import-legacy --directory /private/history \
  --source-root /preserved/terminator --expected-sha256 DIGEST_FROM_PREVIEW
```

The bounded importer recognizes only the exact Active and Resolved tables in
`coordination/SUBMISSIONS.md`. It copies platform, target/title, original status,
severity text, bounty text, and recorded dates, plus file hash and source line.
It omits the Note and Memory Lesson bodies and all request/evidence content.
Unknown dates stay unknown; historical status does not become current status.
Imported rows default to the bug-bounty track, unknown domain, and historical
work state. They can later be explicitly reclassified through an update.

An identical snapshot imports once. A changed source appends a new snapshot
for each existing row and keeps prior states. Stable row identity uses source
path, platform, target, and title. A renamed row becomes a separate case;
automatic merging or deleting of historical rows is intentionally absent.
Table/header drift, ambiguous duplicate identities, or a digest mismatch stops
the import before mutation. The transaction admits the complete import or none
of it. This importer does not migrate the entire old project or all its history.

## Local browser editor

The source-only editor writes directly to the same private history. It supports
case creation, metadata edits, notes and same-case corrections. Saving reloads
the current journal; normal browser reloads retain the local session. Existing
static exports remain available separately.

```text
faultloom history serve --directory /private/history \
  --session-file /private/runtime/editor.access \
  --catalog /private/catalog.json --source-root /references \
  --reference-root archive=/preserved/sources
```

The server binds only `127.0.0.1`. Port `0` chooses an unused port; `--port`
accepts an explicit port. Its console output contains the base URL and session
file location, not a credential. The create-only `.access` file contains a
private launch URL valid for five minutes and one exchange. Open that URL to
enter; it is removed from browser history by the page before the data loads.
The browser then uses an HttpOnly, SameSite=Strict local session cookie for up
to eight hours. The cookie is not Secure because this listener uses HTTP on a
literal loopback address; this is not a remote-hosting configuration.

Without that session, the public page contains only an empty editor shell.
History and optional reference data require a session. Writes additionally
require the exact listener Origin and Host, bounded JSON, and a valid event
contract. Routes are fixed; the server provides no filesystem browsing, shell
command execution, network-target operation, or provider connection.

Each browser save has a unique operation ID and expected journal head. An
identical retry is acknowledged once, even if its original response was lost.
A different concurrent edit is rejected with a refresh-and-review message.
The UI keeps the retry ID while retrying unchanged content in the open form;
after closing or reloading an uncertain form, inspect the latest records
before recreating it. Corrections preserve the original and link to it.

The editor's `자료 연결` form selects a configured origin and source-relative
file path. It captures the current file hash. `사본 보관` archives the linked
version, and `원본 다시 확인` records current source states. The browser verifies
downloaded bytes against the archived hash and size before requesting a save.
Attachment HTTP responses use `application/octet-stream` and attachment
disposition; documents and active content are never embedded for execution.
Source root mappings are configured at startup and cannot be supplied by a web
request. No general filesystem browsing or upload endpoint is provided.

The initial reference page is checked at server startup. Its check time remains
visible; it does not silently refresh original files. Close the foreground
server with Ctrl+C. On restart use a new `.access` filename and launch URL.
These files are credentials, not report attachments or public artifacts.

## Private exports and viewer

```text
faultloom history export --directory /private/history --format html \
  --out /private/view/index.html --reference-page references.html
faultloom knowledge view --catalog /private/catalog.json \
  --source-root /references --out /private/view/references.html --history-page index.html
```

Exports are **decrypted personal copies**, not publication approvals. The HTML
is a static snapshot with search, track/source/work-state filters and a timeline.
Navigation options accept only a sibling HTML filename. No remote assets or
data calls are loaded. Static exports remain read-only; regenerate them under
a new output filename after changing the history. Use `history serve` for the
live editor above.

`--format json` and `--format markdown` are available. Repeat `--case` to export
only selected cases. Export counts describe the selected records; the stored
head remains the source vault checkpoint. Exports and backups never overwrite
existing destinations, and plaintext export inside a Git worktree is rejected.
This is a convenience boundary, not an OS sandbox or a complete publication
scanner. Users who own the key/files can alter them outside the application.

Current limits: 5,000 events, 32 MiB total encrypted event envelopes, 384 MiB database,
64 KiB event, 12,000-character detail, and 1,000 legacy tracker rows. Reference
files use the reference catalogue's bounded text-file capture rules. SQL,
filesystem, key, and integrity failures return a controlled CLI error and exit 2.
Back up before moving the directory; keep original evidence separately.
