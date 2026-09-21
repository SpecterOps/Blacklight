# Blacklight Scout

Blacklight Scout is the **endpoint collection** component of Blacklight. It discovers known AI-tool locations and emits bounded, metadata-only filesystem triage for collection and review.

It does **not** parse session bodies, prompts, responses, credentials, configuration values, SQLite rows, or transcripts. Analyze downloaded artifacts separately with `blacklight sessions <directory>`.

## 1. Choose the artifact

| If you are running on... | Use this artifact | Run it with... |
| --- | --- | --- |
| Windows C2 callback | `ai_path_scout.x64.o` | `execute_coff` and no arguments |
| Windows process / unmanaged PE runner | `ai_path_scout-windows-x64.exe` | `main` |
| Apollo / .NET assembly runner | `ai_path_scout-managed.exe` | `execute_assembly` |
| macOS Poseidon | `libai_path_scout.dylib` | `execute_library`, function `bl_scout_run` |
| Linux Poseidon | `libai_path_scout.so` | `native_call`, function `bl_scout_run` |

All release artifacts are placed in `out/build/scout/` during local builds. Published artifacts, metadata, and checksums are in the GitHub Release bundle.

## 2. Run Scout

### Windows BOF

Use the BOF for a quick, fixed triage snapshot. It accepts no arguments or filters.

```text
execute_coff ai_path_scout.x64.o
```

### Windows executables

Use the native executable with a standard process runner. Use the managed executable with Apollo; do not use the native MinGW EXE with `execute_assembly`.

```text
ai_path_scout-windows-x64.exe
ai_path_scout-windows-x64.exe --include-tool cursor --out assessment.txt
```

```text
register_assembly ai_path_scout-managed.exe
execute_assembly -Assembly ai_path_scout-managed.exe
```

The executable tier accepts `--include-tool`, `--max-depth` (`0` through `4`), `--discovery-cap N`, and `--out`. Tool IDs are `codex`, `claude_code`, `cursor`, `antigravity_cli`, and `grok`; common aliases such as `claude-code`, `antigravity-cli`, and `grok-cli` also work.

### macOS and Linux libraries

The POSIX libraries use a fixed, no-argument interface. Runner-supplied arguments are ignored.

```text
file_path: /tmp/libai_path_scout.dylib
function_name: bl_scout_run
args: []
```

The macOS dylib is universal: it supports Apple Silicon natively and x86_64 through Rosetta.

## 3. Read the output

Scout reports only recognized paths and count-only metadata. For every detected tool it can show compact Config, Rules, Auth, and Sessions summaries, followed by paths for nonempty categories.

Grok support is reconnaissance-only. Scout can rank `updates.jsonl` by filesystem metadata and reports the exact `session_search.sqlite` path. All Scout tiers defer Grok content inspection, and Python Session Analysis does not parse Grok files.

Session results are artifact counts—not conversation counts. The Windows executable tier lists up to three recognized session files by newest modification time and by largest size. Use those results to decide what complete files to collect, then analyze the copies offline:

```bash
blacklight sessions <download-directory>
```

Results can be incomplete when a filesystem limit or access error is reached. Scout marks this with an explicit `[!]` warning and `partial scan` where applicable.

## 4. Know the safety limits

- Scout never follows symbolic links or Windows reparse points.
- Windows executable inspection reads only allowlisted configuration, rules/permission, and authentication text families. It emits counts, never values.
- Session candidates are reported by filesystem path and size only; chat bodies are never read.
- Every endpoint surface stores at most 256 triage targets. The Windows executable tier also limits file inspection to 64 files, 8 MiB per file, and 32 MiB per run.
- Directory discovery is bounded: Windows executable discovery defaults to 5,000 entries, with a separate 10,000-entry session-walk cap. Pass `--discovery-cap N` only when a broader scan is warranted.

## 5. Build Scout

Build the Windows and Linux matrix with Docker (recommended):

```powershell
.\blacklight-scout\build.ps1
```

```bash
./blacklight-scout/build.sh
# equivalent: make -C blacklight-scout release-docker
```

This builds the Windows BOF and native EXE, Linux `.so`, and managed EXE. Build the macOS dylib on macOS, where the Apple SDK and linker are available:

```bash
make -C blacklight-scout release-macos
```

The GitHub Release workflow builds the universal macOS dylib on its macOS runner. Advanced targets (`release-local`, `release-windows`, `release-linux`, and individual native/managed Make targets) are available for CI and specialized hosts.

## More detail

- [Release bundle format and artifact matrix](releases/README.md)
- [Architecture and host boundary](../docs/architecture.md)
- `catalog/targets.json` is the shared source of truth for supported tools and paths.
