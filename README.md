<p align="center">
  <img src="docs/assets/Blacklight_Vertical_WhiteText.png" width="75%" alt="Blacklight: Illuminating AI agent artifacts">
</p>

# Blacklight

Blacklight has two separate phases: **Scout** performs endpoint triage for Codex, Claude Code, Cursor, Antigravity CLI, Grok, Devin CLI, Strands Agents, Kiro CLI, OpenCode, and Muse Code; **Session Analysis** parses selected Codex, Claude Code, Cursor, Antigravity CLI, and Grok chat artifacts. Scout still does not read Grok auth, memory, logs, terminal logs, or session bodies.

## Workflow

1. **Scout the endpoint.** Find candidate session artifacts without reading their bodies.
2. **Choose and download files.** Transfer only the artifacts you want to review.
3. **Analyze downloads.** Create ranked, redacted local reports.

> [!IMPORTANT]
> Blog detailing the project: https://specterops.io/blog/2026/08/12/blacklight-ai-agent-endpoint-artifacts/

## What is in this repository

| Directory | Purpose |
| --- | --- |
| `blacklight-scout/` | Endpoint-native Scout artifacts for bounded metadata triage and session-candidate discovery. |
| `blacklight/` | Python CLI that discovers, parses, prioritizes, and reports on downloaded sessions. |
| `blacklight-rules/` | Defender inventory, exposure review, and detection guidance for these artifacts. |

## Phase 1: Scout the endpoint

Scout performs bounded metadata and filesystem triage. It identifies configuration, rules, authentication metadata, and candidate session paths, but does not read session bodies or print credential/configuration values. Grok reconnaissance covers actionable paths under `.grok`, including auth, config, session state, memory, plugins, skills, logs, and worktree state. Devin CLI, Strands Agents, Kiro CLI, OpenCode, and Muse Code coverage is existence and path enumeration only for known install, config, auth, cache, log, and session-root locations. See the [agent and CLI collection matrix](docs/matrix.md) for full catalog coverage.

### Build Scout

Build the Windows and Linux matrix with Docker:

```powershell
.\blacklight-scout\build.ps1
```

```bash
./blacklight-scout/build.sh
```

Build the macOS library on macOS:

```bash
make -C blacklight-scout release-macos
```

Build products are written to `out/build/scout/`.

| Artifact | Platform | Use |
| --- | --- | --- |
| `ai_path_scout.x64.o` | Windows x64 | No-argument BOF filesystem-triage snapshot. |
| `ai_path_scout-windows-x64.exe` | Windows x64 | Native endpoint assessment executable. |
| `ai_path_scout-managed.exe` | Windows .NET Framework 4.7.2 | Managed endpoint assessment for Apollo. |
| `libai_path_scout.so` | Linux x64 | No-argument filesystem-triage library. |
| `libai_path_scout.dylib` | macOS | No-argument filesystem-triage library. |

### Use Scout

The BOF and POSIX libraries take no filters. Windows executables support tool filtering:

```bash
ai_path_scout-windows-x64.exe --include-tool codex
ai_path_scout-managed.exe --include-tool cursor
```

For artifact interfaces and runner-specific behavior, see the [Scout guide](blacklight-scout/README.md).

## Phase 2: Analyze selected downloads

Install the Python CLI on the analysis host. It requires Python 3.11+.

```bash
python3.11 -m pip install -e .
```

If `blacklight` is not on `PATH`, use `python3.11 -m blacklight`.

Run the CLI against any local directory containing selected JSONL or SQLite artifacts. Files may be flat, nested, renamed, or duplicated when their content has a recognized schema.

Session Analysis parses selected Grok chat artifacts: ACP session updates, chat history, prompt history, and session summaries. Other `.grok/sessions` files, including usage, state, events, logs, and the search database, are recorded as skipped non-session files. Use Scout and Rules for reconnaissance of other Grok paths.

Scout ranks session artifacts by newest activity and size, and reports the recognized artifact volume. For a fast review, download the selected ranked JSONL/SQLite artifacts intact; use the reported total to decide whether to collect more. Scout output and reconstructed endpoint paths are not required: any selected local directory can be analyzed.

```bash
blacklight sessions ~/Downloads/HOST-001 \
  --run-id HOST-001 \
  --output-directory out/results/HOST-001/reports \
  --max-files 10000
```

To analyze known Codex, Claude, Cursor, Antigravity, and Grok session roots in the current user's home directory, run `python3.11 -m blacklight sessions local`. Omitting `local` does the same. This mode skips unrelated home files, including extensions, caches, and logs. An explicit directory or file path retains broad schema discovery.

In local mode, `--tool <codex|claude|cursor|antigravity_cli|grok|grok-cli>` selects that tool's session root. With an explicit path, it remains a detection hint and does not override a conflicting schema. Use `--include`, `--exclude`, `--max-files`, and `--max-file-size` to limit scope. In local mode, `--max-files` counts selected session candidates; with an explicit directory, it retains the encountered-file limit. Add `--json` for a machine-readable terminal summary.

Interactive runs show the current phase, a progress bar with processed/total files when known, and elapsed time. Discovery and report writing use an activity indicator; it keeps moving while a large file is being processed. File counts reset for each phase, and Grok indicator scanning advances after its cross-file deduplication and scanning batch finishes. Progress goes to stderr, so `--json` stdout stays machine-readable. Use `--no-progress` to disable the display; redirecting stderr also suppresses it.

Each run writes a `<RUN_ID>_Session_Report.json` and matching `.txt` report. The text report summarizes coverage, warnings, and the top five sessions per detected tool; the JSON keeps that top selection plus the full ranked sessions, artifact inventory, skipped paths, scanner targets, and redacted indicator metadata. `files_examined` counts encountered files; `session_candidates_examined` counts files considered for parsing. Grok ACP reports logical message counts, completed turns, and raw chunk counts separately. Blacklight does not run external secret scanners; pass selected source files to your approved workflow.

Review skipped, partial, unsupported, ambiguous, and failed input records in the JSON inventory. A file-limit result means discovery was intentionally bounded; it does not stop supported files from being analyzed.

## Documentation

| Guide | When to use it |
| --- | --- |
| [Architecture](docs/architecture.md) | Boundaries, data flow, and parsing limits. |
| [Agent and CLI collection matrix](docs/matrix.md) | Catalog-generated agent, platform, artifact-family, and collection coverage. |
| [Defender Rules](blacklight-rules/README.md) | Inventory, exposure review, and detections. |

## Research and contributions

Blacklight pulled some artifact paths from the [Endpoint AI Agent Abuse
(EAA) technique catalog](https://github.com/0x4D31/endpoint-ai-agent-abuse/blob/main/techniques/index.md).
Contributions that improve endpoint visibility, evidence handling, or defensive
guidance are welcome through issues and pull requests.
