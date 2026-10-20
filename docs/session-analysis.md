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

To analyze known Codex, Claude, Cursor, Antigravity, Grok, OpenCode, and Muse session roots in the current user's home directory, run `uv run --locked blacklight sessions local`. Omitting `local` does the same. This mode skips unrelated home files, including extensions, caches, and logs. An explicit directory or file path retains broad schema discovery.

In local mode, `--tool <codex|claude|cursor|antigravity_cli|grok|grok-cli|opencode|muse_code>` selects that tool's session root. With an explicit path, it remains a detection hint and does not override a conflicting schema. Use `--include`, `--exclude`, `--max-files`, and `--max-file-size` to limit scope. In local mode, `--max-files` counts selected session candidates; with an explicit directory, it retains the encountered-file limit. Add `--json` for a machine-readable terminal summary.

## Progress and reports

Interactive runs show the current phase, a progress bar with processed/total files when known, and elapsed time. Discovery and report writing use an activity indicator; it keeps moving while a large file is being processed. File counts reset for each phase, and Grok indicator scanning advances after its cross-file deduplication and scanning batch finishes. Progress goes to stderr, so `--json` stdout stays machine-readable. Use `--no-progress` to disable the display; redirecting stderr also suppresses it.

Unless `--output-directory` is supplied, reports go to `blacklight-reports/` under the selected directory (beside an individual input file), or `~/blacklight-reports/` in local mode.

Each run writes a `<RUN_ID>_Session_Report.json` and matching `.txt` report. The text report summarizes coverage, warnings, and the top five sessions per detected tool; the JSON keeps that top selection plus the full ranked sessions, artifact inventory, skipped paths, scanner targets, and redacted indicator metadata. `files_examined` counts encountered files; `session_candidates_examined` counts files considered for parsing. Grok ACP reports logical message counts, completed turns, and raw chunk counts separately. Blacklight does not run external secret scanners; pass selected source files to your approved workflow.

Review skipped, partial, unsupported, ambiguous, and failed input records in the JSON inventory. A file-limit result means discovery was intentionally bounded; it does not stop supported files from being analyzed.

## Developer commands

Use the same locked environment for tests and repository scripts:

```bash
uv run --locked python -m unittest discover -s blacklight/tests -v
uv run --locked python blacklight-scout/catalog/generate_targets.py
```

Python 3.11 is selected by `.python-version`; `pyproject.toml` declares runtime dependencies and `uv.lock` pins their resolved versions. After changing dependencies, run `uv lock` and commit both metadata and lockfile changes. `uv sync --locked` and `uv run --locked` reject an outdated lockfile.
