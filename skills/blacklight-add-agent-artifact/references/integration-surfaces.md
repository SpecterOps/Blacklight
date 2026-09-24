# Blacklight integration surfaces

Use this checklist after catalog scaffolding. Search by both the canonical tool id and neighboring supported tools; several surfaces intentionally encode tool-specific behavior.

## Always inspect

- `blacklight-scout/catalog/targets.json`: authoritative cross-platform exact targets.
- `blacklight-rules/catalog/confirmed_artifacts.json`: artifact identity, family, evidence, priority, path kind, and assessment coverage.
- `blacklight/tests/test_targets_catalog.py`: tool scope, root/config minimums, and cross-platform parity.
- `blacklight/tests/test_rules_content.py`: Scout-to-Rules path and family alignment plus detection boundaries.
- `blacklight-scout/releases/ai_path_scout/metadata.json`: advertised tool scope and release contract.
- Operator docs and schema examples that enumerate supported tools.

## Scout behavior

- Regenerate `blacklight-scout/catalog/static_targets_generated.h` and `blacklight-scout/managed/GeneratedTargets.cs`; never hand-edit them.
- Inspect native and managed tool ordering, display names, aliases, filter matching, family matching, and triage priority logic.
- Inspect Windows BOF behavior separately from standalone native and managed Scout behavior.
- Place new human result sections after `ASSESSMENT SUMMARY` and before per-tool details. Match existing uppercase `[i]` headers, four-space status lines, and deeper-indented paths. Use human-readable sizes and correct singular/plural labels. Keep the same section order and wording across all Scout tiers.
- Update `blacklight-scout/releases/ai_path_scout/sample_output.txt` and focused smoke fixtures when changing human output. Assert placement and formatting, not only the presence of keywords.
- Update catalog/header parity tests and smoke fixtures when the tool set changes.

Useful search:

```bash
rg -n 'codex|claude_code|cursor|antigravity_cli' blacklight-scout
```

## Analyze support

- Separate discovery from parsing. Do not add parser evidence to `confirmed_by` until a parser actually consumes the artifact.
- Update config, credential metadata, session detail, high-value, scoring, targeting, and combined-output logic only when applicable.
- Preserve the privacy boundary: no raw secrets or chat text in metadata-facing outputs.
- Update `docs/session-analysis-schema.md` and focused fixtures when emitted shapes or supported tool unions change.
- Ensure partial packages do not invent empty tool records.

Useful search:

```bash
rg -n 'Codex|Claude Code|Cursor|Antigravity CLI|antigravity_cli' blacklight
```

## Rules and detection coverage

- Extend root boundary matching in Rules tests and every relevant query/delivery surface.
- Check Windows object-access, POSIX inventory/exposure, PowerShell ACL, endpoint telemetry, Sigma, Velociraptor, and operator guidance.
- Keep `(tool, family)` values identical between Scout and Rules.
- Exact paths should be present in inventory surfaces unless the catalog marks them as globs.

## Acceptance criteria

- Tool ids, display names, aliases, families, and package directory names are canonical and consistent.
- Windows, macOS, and Linux targets have intentional parity or a documented platform exception with tests.
- Generated files match the source catalog.
- Evidence references resolve to real code/catalog symbols.
- Tests cover the new root boundary or artifact row.
- Documentation describes the actual support tier without overstating parsing or collection.
