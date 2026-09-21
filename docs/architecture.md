# Blacklight Architecture

## Purpose

Blacklight helps an operator and a defender work with local AI-agent artifacts.
Scout and Defender Rules support Codex, Claude Code, Cursor, Antigravity CLI, and Grok artifacts. Python Session Analysis supports the first four tools; Grok is reconnaissance-only and no Grok file-content parser is present.

The repository separates two different tasks:

1. Scout checks an endpoint for known artifact paths and metadata.
2. Session Analysis processes session files that an operator already copied to an analysis host.

This separation is a required security boundary for the normal CLI workflow. Scout does not read session bodies. The `sessions` command does not connect to an endpoint or expand beyond the selected input. The operator selects the files that cross the boundary. The Python package also exposes an explicit direct-root library capability described below.

The repository also contains defender rules. These rules help a defender inventory artifacts and detect file access. The rules do not collect or parse session content.

## Repository Layout

| Path | Function |
| --- | --- |
| `blacklight/` | Python package for analysis of downloaded session artifacts. |
| `blacklight-scout/` | Endpoint Scout source, catalog, build files, tests, and release contracts. |
| `blacklight-rules/` | Defender inventory, detection content, and Windows audit utilities. |
| `docs/` | Operator, release, and architecture documentation. |
| `skills/` | Local agent skills for session analysis and new artifact integration. |
| `.github/workflows/` | Automated release workflow. |
| `out/` | Local build and report output. This directory is generated output, not source. |
| `README.md` | Main workflow and entry point for repository users. |
| `pyproject.toml` | Python package name, version, Python version requirement, and CLI entry point. |
| `CHANGELOG.md` | Release notes source. |
| `.gitignore` | Excludes generated builds, reports, local environments, and local agent state from Git. |

The Python package requires Python 3.11 or later. Its command name is `blacklight`.

## End-to-End Data Flow

The normal flow has four stages.

1. Scout runs on an endpoint and reports recognized artifact paths and limited metadata.
2. An operator selects session files and transfers them to a separate analysis host.
3. The Python CLI detects supported downloaded artifacts and parses them locally.
4. The CLI writes a redacted report and a ranked source-file list for later review.

Scout output is not an input requirement for Session Analysis. The analysis host can process any selected directory. The files can be in nested directories. They can have changed names. Detection uses file structure and supported schemas when possible.

For a focused review, select the newest or largest ranked session artifacts for each agent and transfer complete JSONL or SQLite files to one local directory. The reported session-artifact volume helps decide whether broader collection is needed. Session Analysis writes paired JSON and text reports; use their input inventory to review partial, unsupported, ambiguous, failed, and file-limit results.

The endpoint and analysis-host parts have different content rules.

| Part | May read artifact body | Main output |
| --- | --- | --- |
| Scout BOF and POSIX library | No | Bounded human triage of paths and file metadata. |
| Scout Windows executable | Yes, for known non-session metadata files only | Count-only configuration, rules, and authentication metadata plus session paths. |
| Python `sessions` command | Yes, for files selected by the operator | Local session report with redacted indicators and source paths. |
| Python direct-root library API | Yes, for files below explicitly selected local agent roots | Parser-specific local reports; no transport. |
| Defender Rules | No | Inventory rows, audit configuration, and detection queries. |

## Python Session Analysis

The `blacklight/` directory is the analysis package. It has no endpoint transport feature. Its normal CLI workflow uses local file paths supplied to the `sessions` command. Its exported parser APIs also retain an explicit direct-root mode described under Analysis Engine.

### Command Layer

`blacklight/cli.py` defines the command-line interface. It accepts the `sessions` command and passes the selected limits and filters to the session workflow. It can print a human summary or a JSON terminal summary.

The command supports an input file or directory. It also supports a run identifier, an output directory, a tool hint, include patterns, exclude patterns, a maximum file count, and a maximum file size. A tool hint resolves ambiguous evidence. It does not replace schema detection for a clearly identified artifact.

`blacklight/__main__.py` makes the package runnable as a Python module. `blacklight/__init__.py` identifies the package.

### Session Workflow

`blacklight/sessions.py` coordinates one complete analysis run.

It creates a run identifier when the user does not provide one. It selects a default report directory beside the input. It calls discovery, session-detail parsing, high-value indicator parsing, and session targeting. It then combines the results into one JSON report and one text report.

The workflow keeps supported input files separate from unsupported, ambiguous, skipped, and failed files. A partial parse does not stop other supported files. The final inventory records the parse state for every recognized source.

The workflow ranks sessions from 0 to 100. The rank uses activity, captured content size, response presence, project context, parse health, and redacted high-value indicators. The rank is a review order. It is not a statement that a session is malicious or sensitive.

The workflow also makes scanner targets. A scanner target is an exact source path with a reason for later review. Blacklight does not start a secret scanner or transfer files to another system.

### Input Discovery

`blacklight/session_input.py` finds and classifies downloaded artifacts. Its main data records are `SessionSource`, `SessionInputIssue`, and `SessionInputDiscovery`.

Discovery walks the supplied directory tree with configured file-count and file-size limits. It rejects a top-level symbolic-link input and skips links and special files inside a selected directory. This prevents a link from moving the scan outside the selected input area. It records when a limit stops discovery.

The detector supports JSONL and SQLite inputs. It checks JSONL records for strong tool-specific structures. It checks SQLite files for supported table and schema structures. File names are useful evidence, but names alone do not control a positive result.

The initial supported source types are:

- Codex session, rollout, index, history, and compatible JSONL files.
- Claude Code project, history, subagent, index, and compatible JSONL files.
- Cursor chat `store.db` files and agent transcript JSONL files.
- Antigravity CLI transcript and compatible history JSONL files.
- Antigravity conversation SQLite files for schema and count metadata.

Cursor SQLite stores use a temporary immutable, read-only copy of the selected database file. Session Analysis does not probe or copy adjacent WAL or SHM sidecars. An operator who needs uncheckpointed WAL content must checkpoint it into the database before staging the selected file.

### Analysis Engine

`blacklight/analyze.py` contains the parsers and targeting logic.

The session-detail parser recovers session identifiers, activity counts, timestamps, response-capture state, title context, project or worktree context, source coverage, and parse health. It normalizes records from different tools into a common session form.

The high-value parser examines supported text fields during the analysis run. It uses fixed indicator rules for categories such as credential-like values, internal hosts, network targets, cloud identity values, and source-control values. It stores category, count, severity, and a hash of a canonical value. It does not store the raw matched value in the report.

The targeting layer joins session detail with high-value results. It selects the most useful source path for a recovered session from the accepted input sources. It handles aggregate files and subagent files without searching sibling agent roots or adding paths that discovery did not accept. It produces per-session rows and aggregate counts.

`blacklight/common.py` provides shared support. It creates report envelopes, normalizes safe file-name text, reads JSON and JSONL, flattens structured values, extracts text fragments, calculates hashes, resolves input roots, and writes JSON and text outputs. It also provides host and collection time metadata.

### Direct-Root Library Capability

The exported `run_session_detail`, `run_session_high_value`, and `run_session_targeting_report` functions accept `package_root`, `target_root`, `live_root`, and tool-specific root arguments. `live_root=True` defaults to the current user's Codex, Claude Code, Cursor, and Antigravity CLI roots. These programmatic modes enumerate and parse supported files below those local roots. They do not execute recovered content, reuse credentials, or provide network transport.

The `sessions` CLI does not expose direct-root mode. Direct-root calls do not use the CLI's `max_files` and `max_file_size` discovery limits, so callers must invoke them only against a deliberately selected local root and apply any required host-level safeguards.

### Reports and Sensitivity

The default report directory is `blacklight-reports` below an input directory, or beside an input file. Each run writes one JSON file and one text file. The file name contains the run identifier and `Session_Report`.

The report includes these sections:

- run, host, operating system, user, input, and output context;
- content policy for the report;
- summary counts and parse-health counts;
- artifact inventory and discovery issues;
- ranked session rows;
- hashed high-value indicator metadata; and
- external scanner target paths.

The report does not include raw message text or raw credential values. It includes source paths, session titles, project context, timestamps, and hashes when the input provides them. These fields can reveal operational information. Treat all reports as sensitive evidence.

## Scout

`blacklight-scout/` is the endpoint part of Blacklight. It finds known local artifact paths and emits bounded triage. It supports Windows, Linux, and macOS delivery surfaces.

Scout uses five stable tool identifiers: `codex`, `claude_code`, `cursor`, `antigravity_cli`, and `grok`. It also accepts common operator aliases in the Windows executable interfaces.

### Scout Catalog

`blacklight-scout/catalog/targets.json` is the canonical path catalog. It defines known artifacts, tool IDs, artifact families, platforms, and path patterns.

`blacklight-scout/catalog/generate_targets.py` generates language-specific catalog data from that JSON file. The generated C header is `static_targets_generated.h`. The managed source also receives generated target data during the build process. This design keeps native and managed Scout coverage aligned.

The Defender inventory content uses the same catalog vocabulary and path coverage. The Python tests check this alignment.

### Native Shared Core

`blacklight-scout/native/ai_path_scout_core.c` and `ai_path_scout_core.h` contain shared native functions. They normalize tool filters, match allowed tools, assign triage priority, expand known target patterns, and scan static targets.

The shared core returns records through platform-specific callback functions. Each platform implementation decides how to test a path, list a directory, expand an environment path, and print the result.

### Windows Native Executable

`blacklight-scout/native/ai_path_scout_windows.c` builds the Windows standalone executable. It supports optional tool filters, output-file selection, maximum-depth control, and dynamic-discovery budget control.

The executable checks recognized configuration, rules, authentication, and session locations. It can inspect allowlisted non-session text files for count-only metadata. It does not print configuration values, credentials, identities, project names, commands, endpoints, or chat text. It does not inspect SQLite rows or session bodies.

The executable ranks up to three recognized session candidates for each detected tool. It reports their paths and sizes. It reports other recognized paths as a count.

File reading has fixed limits. The executable inspects at most 64 files, up to 8 MiB per file, and up to 32 MiB for one run. Directory traversal has hard entry and depth limits. It does not follow Windows reparse points. It marks output as partial when an access error or a limit prevents complete work.

### Windows BOF

`blacklight-scout/native/ai_path_scout_bof.c` builds the Windows x64 BOF. Its entry point is `go`.

The BOF is a no-argument callback snapshot. It does not accept a filter. It reads file metadata and bounded directory listings only. It never reads artifact bodies.

It groups output by collection priority and tool. It reports discovered paths, compact counts, and ranked session candidates. It uses fixed storage for recognized targets and emits an incomplete-results warning if that storage or a discovery budget is full.

`beacon.h` provides the Beacon API declarations needed to build the BOF without a full Beacon SDK source dependency.

### POSIX Library and Standalone Form

`blacklight-scout/native/ai_path_scout_posix.c` implements the Linux shared object, macOS dynamic library, and a POSIX standalone form. The library entry point is `bl_scout_run`, which returns a heap copy of its bounded output through Poseidon's `char *(int argc, char **argv)` native-module ABI. The standalone form writes that returned output to stdout and frees it.

This surface is no-argument and unfiltered. Supplied standalone command tokens are ignored. It produces the same fixed human-triage form as the BOF. It checks paths, file metadata, and bounded directory listings. It never reads artifact bodies.

The POSIX implementation does not follow symbolic links. It has separate limits for session discovery, dynamic discovery, child counting, stored targets, and traversal depth. It reports partial results when a limit or access error occurs.

### Managed Windows Assembly

`blacklight-scout/managed/Program.cs` implements the .NET Framework 4.7.2 assembly for managed Windows runners. The project file is `ai_path_scout-managed.csproj`.

The managed assembly uses generated catalog targets and has the same endpoint boundary as the native Windows executable. It supports tool filtering and bounded dynamic discovery. It emits a human assessment with count-only metadata and session candidate paths. It does not emit raw secrets or session bodies.

The managed assembly is for runners that load a .NET assembly. The BOF and native executable have different runner contracts. These artifacts must not be substituted without checking the runner type.

### Dynamic Discovery and Limits

Some session and rules locations use dynamic discovery because a path contains user-created names. Scout reserves dynamic scan capacity for each root. A large directory for one tool cannot use the full budget for another tool.

All Scout surfaces use collection boundaries:

- They do not follow links or reparse points.
- They continue after an inaccessible entry when possible.
- They stop at fixed entry and depth budgets.
- They store at most 256 recognized targets.
- They mark incomplete output when a cap or access failure affects results.

The Windows executable and managed assembly can inspect non-session metadata under their fixed inspection limits. The BOF and POSIX surfaces cannot. This difference is intentional.

## Scout Builds and Releases

`blacklight-scout/Makefile` defines Scout build targets. `build.ps1` and `build.sh` are host wrappers for the normal Docker build. `Dockerfile` and `docker-entrypoint.sh` define the container build environment for the Windows and Linux matrix.

The container build produces the Windows BOF, Windows native executable, Windows managed executable, and Linux shared object. A macOS dynamic library must be built on macOS because it needs the Darwin toolchain.

Local build products go under `out/build/scout/`. Source directories must not contain compiled Scout artifacts.

`blacklight-scout/releases/` defines release bundle content. `metadata.json` records loader and entry-point contracts. `sample_output.txt` is a sanitized output example. `verify_matrix.py` checks metadata and expected build files.

`.github/workflows/release.yml` builds and publishes tagged Scout releases. It checks version agreement, catalog generation, artifact presence, release metadata, and the Windows executable smoke test. The Python unit suite is a separate required check before a release tag.

## Defender Rules

`blacklight-rules/` is for defensive monitoring of local AI-agent artifact access. It does not execute Scout and does not parse session files.

### Inventory

`blacklight-rules/inventory/` contains osquery SQL files for Windows and POSIX inventory. They identify known paths and return metadata needed for monitoring decisions. The POSIX exposed-artifacts query identifies high-value artifacts that are readable by a group or by all users.

The inventory queries use the same artifact families as the Scout catalog. They should run before telemetry changes so a defender can limit monitoring to installed tools and useful paths.

### Detection

`blacklight-rules/detection/windows/telemetry.md` contains the complete Windows
workflow: audit-policy and SACL setup, local validation, rollback, and query
forms for Splunk, Microsoft Sentinel, Elastic Security, Google SecOps, and
Microsoft Defender XDR.

Windows object-access detections use Security event 4663 with file-object and read or directory-list access conditions. These records can show that a process read or listed an in-scope path when Windows auditing and a matching SACL are active. A command-line reference to a path is only context. It does not prove file access.

`blacklight-rules/detection/linux/osquery-file-events.conf` and
`blacklight-rules/detection/macos/osquery-file-events.conf` configure the
platform-local osquery file-event profiles. They report file-change activity on
Linux and macOS. On Linux, an optional access mode can report access events.
macOS FSEvents does not provide equivalent proof of reads. A defender must use
suitable endpoint-security telemetry when proof of reads is required.

### Windows Utilities

`blacklight-rules/powershell/Invoke-BlacklightWindowsTelemetry.ps1` reviews, applies, or rolls back Windows file-system audit configuration with self-cleaning rollback state (SACL and audit-policy only). Changes require an approved administrative change.

`blacklight-rules/catalog/confirmed_artifacts.json` records confirmed artifact coverage for the defender content.

## Tests and Quality Controls

The Python tests are in `blacklight/tests/`.

`test_sessions.py` checks session discovery, parsing, report behavior, limits, and redaction-related output behavior. `test_targets_catalog.py` checks that catalog definitions remain aligned across relevant components. `test_rules_content.py` checks expected defender-rule content. `test_release_version.py` checks release version consistency.

`blacklight-scout/tests/exe_triage_smoke.ps1` runs a Windows executable smoke test with a controlled fixture. `blacklight-scout/native/smoke_test.sh` supports native smoke checks. The release verifier checks release-bundle metadata and files.

Tests validate expected behavior. They do not prove that every endpoint path exists or that a defender telemetry deployment is complete. Operators and defenders must validate those conditions in their own environment.

## Documentation and Agent Skills

The README contains the concise operator workflow; this document defines its boundaries, data flow, and processing limits.

`.github/workflows/release.yml` is the release procedure. It defines the tagged artifact build, verification, packaging, and publishing checks.

`skills/session-analysis/` provides guidance for interpreting Blacklight session-analysis output. `skills/blacklight-add-agent-artifact/` provides a structured process and references for adding support for another agent artifact. These skills support consistent maintenance. They are not part of the runtime data path.

## Operational Boundaries

Use the following rules when operating or changing Blacklight:

1. Do not add transcript-body parsing to Scout.
2. Do not add endpoint transport to the Python analysis package. Keep direct-root discovery explicit to the documented library API, and keep the `sessions` CLI limited to its selected input.
3. Keep raw credential values and raw matched indicator values out of reports.
4. Keep catalog changes aligned across Scout, defender inventory, and tests.
5. Treat paths, session titles, project context, timestamps, and hashes as sensitive data.

These boundaries keep endpoint triage bounded, make offline analysis explicit, and give defenders focused coverage for local artifact access.
