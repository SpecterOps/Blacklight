# Discovery-only session roots

Run commands from the Blacklight repository root after [setting up uv](../README.md#phase-2-analyze-selected-downloads).

Run `uv run --locked python -m blacklight.artifact_roots --tool strands` on the source machine to print existing session storage directories as JSON. This metadata helper reads the Strands root registry, not conversation bodies. It does not transfer artifacts or add a session parser.

The helper follows `~/.strands/cli/session-roots.json` version 1 entries using `roots[].directory`, which points to the actual store, rather than appending a path to `roots[].workspace`. Strands defaults to project `./.agent/sessions/`, but a registered store can be elsewhere. The registry schema is defined in upstream [SessionRootCatalog](https://github.com/strands-agents/harness-sdk/blob/main/strands-cli/src/tui/session/catalog.ts). Missing stores, relative paths, and symlink paths are skipped. Malformed registries, unknown versions, registries above 1 MiB, and lists above 1,024 entries return no roots.

Select the returned directories explicitly for collection, preserving companion files and offloaded tool results. An empty result does not prove no sessions exist: registry entries may be absent, sessions may be cloud-backed, or custom stores may not be registered.

Run `uv run --locked python -m blacklight.artifact_roots --tool kiro` for existing Kiro CLI and legacy database roots. Set `KIRO_SESSIONS_DIR` to an absolute custom collection directory to replace the defaults. This is a Blacklight collector override; it is not a claim about a variable understood by Kiro itself. Collect complete session stores and their companion files; cloud-only sessions can leave no local root.

Run `uv run --locked python -m blacklight.artifact_roots --tool devin` for existing default Devin CLI data directories, or set `DEVIN_SESSIONS_DIR` to an absolute directory to replace them. The override belongs to this collection helper. A returned directory is a collection lead, not proof that `sessions.db` exists. Preserve adjacent WAL/SHM files when collecting a database. Overrides must be absolute paths; `~` and relative paths are rejected instead of resolving against another user's home or the current directory.
