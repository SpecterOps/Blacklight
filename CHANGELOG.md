# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where applicable.

## [Unreleased]

### Added

- Session Analysis now shows live terminal progress during discovery, artifact identification, session parsing, indicator scanning, and report writing, with per-phase file counts and elapsed time. The display stays active during slow files, writes to interactive stderr to preserve JSON stdout, and can be disabled with `--no-progress`.

### Fixed

- Windows executable smoke tests now derive the expected version from release metadata instead of requiring the stale `0.2.0` version.

## [0.2.5] - 2026-10-15

### Added

- Reconnaissance-only Muse Code (`muse_code`, aliases `muse` and `muse-code`) support across Scout and Defender Rules. Scout reports existence and enumerates known home-relative install, config, auth, session, skill, plugin, cache, log, and workspace paths (`~/.config/muse`, `~/.local/share/muse`, `~/.muse/projects`, and Windows `AppData/Local/Programs/muse`). Scout does not parse `auth.json`, session bodies, or SQLite indexes. Project-relative markers remain documentation-only reference context in the architecture guide.
- Reconnaissance-only Kiro CLI and OpenCode support across Scout and Defender Rules. Scout reports existence and enumerates known home-relative install, config, auth, session, cache, log, MCP, skill, rules, and plugin paths (including legacy Amazon Q paths under `kiro`). Scout does not parse SQLite, `auth.json`, or session bodies for these tools. The generated `docs/matrix.md` summarizes coverage for all Scout tools.
- Reconnaissance-only Devin CLI and Strands Agents support across Scout and Defender Rules. Scout reports existence and enumerates known install, config, auth, cache, log, and session-root paths mined from Devin install scripts/docs and the `@strands-agents/cli` package. Scout does not parse credentials or session bodies for these tools.
- Session Analysis parses selected Grok chat artifacts: ACP session updates, chat history, prompt history, and session summaries. It does not parse Grok auth, memory, logs, terminal logs, or Scout bodies.

### Changed

- Consolidated all ten Scout/Rules tool IDs into the generated `docs/matrix.md`; preserved tool aliases and project-marker limitations in the architecture guide.
- Grok session discovery skips non-chat state and telemetry files, preventing false parse failures and cross-tool sessions. ACP message chunks are grouped into logical messages with separate turn and chunk counts; text reports show a compact review while JSON retains the full inventory.

### Fixed

- Repaired the macOS scheduled artifact inventory SQL for Strands, Kiro, OpenCode, and Muse Code; release CI now runs the complete Python suite on Linux, including compilation checks for Rules inventory and scheduled SQL.
- Managed Scout now matches native Scout's filesystem timestamp fallback for session locations with no ranked session files. Windows smoke fixtures use fixed Claude session timestamps and cover recon-only tool filters, aliases, body-inspection boundaries, missing paths, and native/managed parity.
- Restored the canonical release checklist referenced by metadata and release tests.

## [0.2.1] - 2026-09-21

### Added

- Reconnaissance-only Grok support across Scout and Defender Rules for actionable `.grok` authentication, configuration, session, memory, plugin, skill, log, and worktree paths. Grok file-content parsing remains intentionally deferred.

## [0.2.0] - 2026-07-23

### Added

- Downloaded-session analysis for Codex, Claude Code, Cursor, and Antigravity CLI, including schema-based recognition of renamed artifacts and redacted, ranked reports.
- Cross-platform Scout release artifacts: Windows BOF, native executable, managed assembly, macOS dylib, and Linux shared object.
- Blacklight Rules inventory, ACL-review, Velociraptor, Sigma-style, and osquery guidance grounded in the shared artifact catalog.

### Removed

- Retired Python `handoff`, `analyze`, and `workflow local` commands; the installed CLI exposes `sessions`.
- Removed Scout machine-output modes; endpoint artifacts emit bounded human-readable assessment or filesystem-triage output.

### Changed

- The primary workflow is endpoint assessment or filesystem triage, selective transfer, then `blacklight sessions <download-directory>` on the operator host.
- The README is the authoritative operator workflow; `docs/RELEASE.md` is the release checklist.

### Fixed

- Continued POSIX session discovery after local access failures and reported all traversal/result cap exhaustion as partial output.
- Restored count-only Windows configuration assessment by suppressing provider, model, policy, sandbox, and reasoning values.
- Rejected mismatched release tags and published release metadata and representative output with the five Scout binaries and checksums.

## [0.1.0] - 2026-07-07

### Added

- PyInstaller one-file CLI (`blacklight` / `blacklight.exe`) with cross-platform CI release builds and binary smoke tests.
- Shared target catalog synced across BOF, Python Scout, and native loaders (`blacklight-scout/catalog/targets.json`).
- Blacklight Scout BOF `ai_path_scout` with `BLACKLIGHT_PATH` v1 output.
- macOS dylib (`libai_path_scout.dylib`) and Linux shared object (`libai_path_scout.so`) native Scout loaders with smoke tests.
- BOF release bundle with metadata, sample output, and release checklist under `blacklight-scout/releases/ai_path_scout/`.
- Blacklight Analyze parsers for Codex, Claude Code, Cursor, and Antigravity CLI.
- Session targeting reports with JSON, CSV, status CSV, and compact text outputs.
- Initial Blacklight Rules content (osquery, Velociraptor, Sigma-style) and regression tests.
- `docs/RELEASE.md` operator release checklist and v0.1.0 tag instructions.
- `blacklight workflow local` for one-shot discover, collect, and analyze on the operator host.
- `blacklight workflow local --in-place` (default when `--package-root` is omitted) for live-root analysis without copying files.
- Console script entry point: `blacklight` after `pip install -e .`.

### Changed

- `blacklight workflow local` defaults to in-place analysis when `--package-root` is omitted.

### Fixed

- Windows test teardown `PermissionError` when SQLite fixture files remained locked after analysis tests.

### Documentation

- README and architecture documentation â€” operator workflow, boundaries, and analysis guidance.
- Collapsed `docs/BlackLight_Blog_Draft.md` to public-blog outline with execution modes in the workflow section.
