---
name: blacklight-add-agent-artifact
description: Add a newly supported AI agent/tool or a newly discovered artifact file, directory, or glob to Blacklight while keeping Scout and Rules catalogs, generated target tables, schemas, and validation surfaces aligned. Use for requests to add agent support, register an artifact path, extend an existing agent directory inventory, or scaffold cross-platform target metadata.
---

# Blacklight Add Agent or Artifact

Add the catalog baseline deterministically, then complete the code surfaces that require semantic decisions. Treat an "agent" as an AI coding/agentic tool supported by Blacklight, not as a Codex subagent profile.

## Choose the operation

- **New agent/tool**: require a canonical tool id, home-relative root, and at least one config path. Use `add-agent`.
- **New artifact**: require the existing tool id, stable artifact id, family, home-relative path, path kind, priority, evidence source, and assessment coverage. Use `add-artifact`.
- **Codex custom subagent**: do not use this workflow. Project profiles belong in `.codex/agents/*.toml` and use the Codex custom-agent schema.

## Establish evidence first

1. Confirm the path from sanitized documentation, a lab system, or existing parser behavior.
2. Never copy credential values, session content, host-identifying paths, or raw evidence into catalogs, fixtures, docs, or prompts.
3. Classify the path with the existing family vocabulary whenever possible: `root`, `auth`, `config`, `mcp`, `sessions`, `history`, `workspace`, `rules`, `plugins`, `extensions`, `skills`, `plans`, `telemetry`, `sandbox`, `cache`, or `logs`.
4. Use `explicitly_assessed` only when Scout targets the exact path. Use `recursively_discovered` for bounded descendant matching and `intentionally_deferred` when cataloged without collection or parsing.

## Scaffold the catalogs

Run from the repository root. Omit `--write` for a preview.

```bash
python skills/blacklight-add-agent-artifact/scripts/scaffold.py --write add-agent \
  --tool example_agent \
  --root-path .example-agent \
  --config-path .example-agent/settings.json
```

```bash
python skills/blacklight-add-agent-artifact/scripts/scaffold.py --write add-artifact \
  --tool cursor \
  --artifact-id cursor.example_state \
  --family workspace \
  --relative-path .cursor/example-state.json \
  --path-kind file \
  --priority medium
```

Use `--rules-only` for globs, recursively discovered paths, and intentionally deferred artifacts that must not become exact Scout targets. Add `--analyze-confirmed` only when the named path is actually consumed by `run_session_detail`.

The script updates:

- `blacklight-scout/catalog/targets.json`
- `blacklight-rules/catalog/confirmed_artifacts.json`
- `blacklight-scout/catalog/static_targets_generated.h`
- `blacklight-scout/managed/GeneratedTargets.cs`

It refuses duplicate ids, duplicate paths, unknown tools, invalid home-relative paths, glob Scout targets, and inconsistent coverage choices.

## Complete semantic integration

Read [integration-surfaces.md](references/integration-surfaces.md) after scaffolding. Inspect each listed surface and change only those required by the requested support level. A new catalog row does not imply parsing support.

For new Scout output, follow the repository's human assessment layout: place a dedicated uppercase section after `ASSESSMENT SUMMARY`, use indented status and path lines, and keep native, BOF, managed, and POSIX output in sync. Update the release sample output and the affected smoke fixtures with the same layout.

For a new agent, explicitly decide and document whether the change is:

- discovery-only,
- metadata triage,
- Analyze parsing,
- Rules/detection coverage, or
- full end-to-end support.

Do not claim a broader level than the implemented and tested surfaces establish.

## Validate

Run the focused gates:

```bash
python blacklight-scout/catalog/generate_targets.py
python -m unittest blacklight.tests.test_targets_catalog blacklight.tests.test_rules_content -v
```

Then run tests for every semantic surface changed. Review `git diff` for generated-file drift, cross-platform path parity, canonical family alignment, secret leakage, and unrelated edits.
