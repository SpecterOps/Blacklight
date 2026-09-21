# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where applicable.

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
- The README is the authoritative operator workflow; tagged GitHub Actions workflows handle release builds and publishing.

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
- BOF release bundle with metadata and sample output under `blacklight-scout/releases/ai_path_scout/`.
- Blacklight Analyze parsers for Codex, Claude Code, Cursor, and Antigravity CLI.
- Session targeting reports with JSON, CSV, status CSV, and compact text outputs.
- Initial Blacklight Rules content (osquery, Velociraptor, Sigma-style) and regression tests.
- `blacklight workflow local` for one-shot discover, collect, and analyze on the operator host.
- `blacklight workflow local --in-place` (default when `--package-root` is omitted) for live-root analysis without copying files.
- Console script entry point: `blacklight` after `pip install -e .`.

### Changed

- `blacklight workflow local` defaults to in-place analysis when `--package-root` is omitted.

### Fixed

- Windows test teardown `PermissionError` when SQLite fixture files remained locked after analysis tests.

### Documentation

- README and architecture documentation — operator workflow, boundaries, and analysis guidance.
- Collapsed `docs/BlackLight_Blog_Draft.md` to public-blog outline with execution modes in the workflow section.
