# Session analysis guide

Run these commands from the repository root after [setting up uv](../README.md#phase-2-analyze-selected-downloads).

## Selected downloads

Run the CLI against any local directory containing selected JSONL, Zstandard-compressed Codex JSONL (`.jsonl.zst`), or SQLite artifacts. Files may be flat, nested, renamed, or duplicated when their content has a recognized schema. Compressed Codex sessions are read as streams; reports retain the source path and on-disk size, while `--max-file-size` also limits expanded data.

Session Analysis parses selected Grok chat artifacts: ACP session updates, chat history, prompt history, and session summaries. Other `.grok/sessions` files, including usage, state, events, logs, and the search database, are recorded as skipped non-session files. Use Scout and Rules for reconnaissance of other Grok paths.

Scout ranks session artifacts by newest activity and on-disk size, and reports the recognized artifact volume. It recognizes `.jsonl.zst` Codex candidates by filesystem metadata without reading their contents. For a fast review, download the selected ranked JSONL/SQLite artifacts intact; use the reported total to decide whether to collect more. Scout output and reconstructed endpoint paths are not required: any selected local directory can be analyzed.

```bash
uv run --locked blacklight sessions ~/Downloads/HOST-001 \
  --run-id HOST-001 \
  --output-directory out/results/HOST-001/reports \
  --max-files 10000
```

## Local sessions and scope

To analyze known Codex, Claude, Cursor, Antigravity, Grok, OpenCode, and Muse session roots in the current user's home directory, run `uv run --locked blacklight sessions local`. Omitting `local` does the same. This mode skips unrelated home files, including extensions, caches, and logs. The additional Codex and Cursor defender inventory and deferred collection paths are not local session candidates. An explicit directory or file path retains broad schema discovery.

In local mode, `--tool <codex|claude|cursor|antigravity_cli|grok|grok-cli|opencode|muse_code>` selects that tool's session root. With an explicit path, it remains a detection hint and does not override a conflicting schema. Use `--include`, `--exclude`, `--max-files`, and `--max-file-size` to limit scope. In local mode, `--max-files` counts selected session candidates; with an explicit directory, it retains the encountered-file limit. Add `--json` for a machine-readable terminal summary.

## Progress and reports

Interactive runs show the current phase, a progress bar with processed/total files when known, and elapsed time. Discovery and report writing use an activity indicator; it keeps moving while a large file is being processed. File counts reset for each phase. Sessions are parsed once for metadata; there is no indicator-scanning phase. Progress goes to stderr, so `--json` stdout stays machine-readable. Use `--no-progress` to disable the display; redirecting stderr also suppresses it.

Unless `--output-directory` is supplied, reports go to `blacklight-reports/` under the selected directory (beside an individual input file), or `~/blacklight-reports/` in local mode.

Each run writes a `<RUN_ID>_Session_Report.json` and matching `.txt` report. The text report summarizes coverage, warnings, and the top five sessions per detected tool; the JSON keeps that top selection plus the full ranked sessions, artifact inventory, skipped paths, scanner targets, and scoring explanations. `files_examined` counts encountered files; `session_candidates_examined` counts files considered for parsing. Grok ACP reports logical message counts, completed turns, and raw chunk counts separately. Blacklight does not run external secret scanners; pass selected source files to your approved workflow.

Review skipped, partial, unsupported, ambiguous, and failed input records in the JSON inventory. A file-limit result means discovery was intentionally bounded; it does not stop supported files from being analyzed.

## Session score: `activity-v1`

The score orders sessions for review using captured size, logical message volume, recency, and recent project session frequency. It does not estimate sensitivity or detect secrets. Titles, response status, project presence alone, and parse success do not award points.

```text
size_points      = 40 × B / (B + 65,536)
message_points   = 30 × M / (M + 20)
recency_points   = 20 × 2^(-A / 30)
frequency_points = 10 × F / (F + 4)
raw_score        = size_points + message_points + recency_points + frequency_points
blacklight_score = min(99, floor(raw_score))
```

| Input | Meaning |
| --- | --- |
| `B` | Nonnegative `captured_total_bytes`: extracted request, response, and tool-event content bytes. Excludes machine context and JSON/container overhead; compressed on-disk size is not used. |
| `M` | Nonnegative request count plus nonnegative response count. Grok uses logical messages, not raw ACP chunks. |
| `A` | Days since the session's `last_activity`, measured against one UTC reference time captured at run start. |
| `F` | Other distinct sessions active within the preceding 30 days, inclusive, in the same tool and exact nonempty project/worktree path. |

Size and message volume have diminishing returns: 64 KiB earns 20 size points, 20 messages earn 15 message points. Recency has a 30-day half-life: activity now earns 20 points, activity 30 days ago earns 10. Four recent project peers earn 5 frequency points. For a session with all four of those midpoint inputs, the score is **50**. A session with 1 MiB, 100 messages, activity now, and no project peers scores **82** (37.65 + 25 + 20 + 0, rounded down).

Missing counts and byte sizes are zero; negative counts and sizes are clamped to zero. Missing or invalid timestamps earn zero recency points and do not contribute to frequency counts. Timezone-free timestamps are interpreted as UTC. Future timestamps are treated as age zero, including for the frequency window. Missing project paths earn zero frequency points. Different worktree paths remain separate groups; paths are not resolved against the analysis computer's filesystem.

Frequency counts use recovered sessions after existing parser deduplication, with distinct identities defined by tool and session ID, and exclude the session being scored. Even an older session can receive points for recent peers in its project. Counts cover only the selected inputs, so filters, collection scope, or discovery limits can change this component. The other constants are fixed across tools and runs; elapsed time changes recency.

Finite inputs approach 100 without reaching an early component cap. Integer scores range from 0 through 99. Ranking uses the unrounded total, then captured bytes, then normalized activity time (all descending), followed by tool and session ID (ascending) for deterministic ties. Equal displayed integers can therefore have different ranks.

Both JSON output forms include a top-level `scoring` description with the version, formula, and `reference_time_utc`. Each ranked session includes `scoring` inputs, four point contributions, `raw_score`, and the displayed integer. Text reports include the formula. Report content policy sets `sensitivity_scoring_included` to `false`.

The indicator feature and its Python `run_session_high_value` API have been removed. New reports omit `indicator_categories`, `high_value_detail`, indicator totals, match totals, and high-value summary scores. External scanner target paths remain available for a separate approved review workflow.

## Developer commands

Use the same locked environment for tests and repository scripts:

```bash
uv run --locked python -m unittest discover -s blacklight/tests -v
uv run --locked python blacklight-scout/catalog/generate_targets.py
```

Python 3.11 is selected by `.python-version`; `pyproject.toml` declares runtime dependencies and `uv.lock` pins their resolved versions. After changing dependencies, run `uv lock` and commit both metadata and lockfile changes. `uv sync --locked` and `uv run --locked` reject an outdated lockfile.

## Cursor IDE and project acquisition

Cursor uses both `~/.cursor` and a separate IDE application-data root:

| Platform | IDE root, relative to the user's home |
| --- | --- |
| macOS | `Library/Application Support/Cursor` |
| Windows | `AppData/Roaming/Cursor` |
| Linux | `.config/Cursor` |

Scout inventories `User/globalStorage/state.vscdb`, `state.vscdb.backup`,
`conversation-search.db`, and their adjacent `-wal`/`-shm` files when present.
It also discovers `User/workspaceStorage/<workspace-id>/state.vscdb`, its backup,
and companions. These IDE databases are inventory/collection leads; Session
Analysis does not yet parse their chat, authentication, or search-index contents.
Search-index entries are not proof of complete conversations or tool traces.

Under `.cursor/projects/<project>/`, bounded Scout discovery reports files in
`terminals/` (terminal context and captured terminal text) and `agent-tools/`
(tool output, potentially including sensitive data). This does not guarantee
complete command history or reliable conversation/tool-call attribution. These
files are inventoried without reading bodies and are not yet content-scanned by
Session Analysis. `worker.log` remains deferred and is not individually emitted.
Discovery is depth-, entry-, and output-bounded; incomplete results are reported.
Symbolic links/reparse points are not traversed by these dynamic walkers.

For `.cursor/chats/**/store.db`, collect its exact adjacent `store.db-wal` and
`store.db-shm` when present, preserving the basename and directory layout. Apply
the same acquisition rule to IDE databases and backups. WAL files can hold
committed changes absent from the main database; SHM is coordination metadata,
and its absence alone does not establish missing committed content. Companion
files are not independent sessions. The existing SQLite snapshot reader uses
adjacent sidecars for supported database inputs without modifying the originals.

Scout does not transfer files. Acquire a consistent snapshot or quiesce Cursor
before operator download: sequential copying of a live database and sidecars is
not guaranteed consistent. No credential decryption is performed.

### Antigravity conversation indexes

Session Analysis recognizes `cache/conversation_metadata.json` and
`jetbox_summaries_proto.pb` in local mode and selected downloads. Index records
merge with transcripts by conversation ID. Index-only conversations have no
captured request/response counts. JSON summary fields (including previews, step
counts, workspace URIs, and update times) remain in `index_metadata` with their
source paths in the JSON report.

The protobuf reader supports the observed AGY 1.5.9 repeated conversation-summary
layout. It extracts the conversation ID, summary title, workspace URIs, and
readable nested fields. Numbered `protobuf_text_fields` retain repository URLs,
branches, and other readable values with their wire-field provenance; unknown
field meanings are not inferred. Malformed wire data is reported as a parse
failure. Opaque `implicit/*.pb` files remain outside parser coverage.

Scout reports selected index paths and filesystem metadata. SQLite WAL and SHM
files belong with their main database when collecting evidence; Session Analysis
copies exact sidecars into its temporary read-only snapshot. Presence lock files
alone do not prove that a conversation is currently active.
