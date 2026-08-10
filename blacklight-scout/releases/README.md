# Blacklight Scout Release Bundles

This directory holds machine-readable Scout release metadata and representative output. The canonical human release gate is [`docs/RELEASE.md`](../../docs/RELEASE.md).

Local release builds place binaries in `out/build/scout/`; compiled binaries are published through GitHub Releases rather than stored here.

## Current Bundle

| Bundle | Path | Platforms | Entrypoints |
| --- | --- | --- | --- |
| `ai_path_scout` | [`ai_path_scout/`](ai_path_scout/) | Windows BOF/native/managed, macOS dylib, Linux `.so` | `go`, `main` / `Main`, `bl_scout_run` |

The root [`metadata.json`](metadata.json) indexes bundles. Each bundle contains its detailed `metadata.json` and representative `sample_output.txt`.

## Contract Summary

- The bundle version must match the Git tag; the output contract remains `v1`.
- macOS/Linux libraries and standalone builds always emit grouped, body-free human filesystem triage.
- POSIX builds take no arguments; supplied CLI tokens are ignored.
- Windows native and managed executables always emit bounded human assessment with up to three ranked session files per tool; unused Windows machine modes and `--verbose` were removed.
- `blacklight-scout/catalog/targets.json` is the catalog source of truth. The generator derives the native C and managed C# target tables.

Representative records and summary banners are in [`ai_path_scout/sample_output.txt`](ai_path_scout/sample_output.txt).

## Artifact Matrix

| Platform | Artifact | Architecture | Loader / entrypoint |
| --- | --- | --- | --- |
| Windows | `ai_path_scout.x64.o` | x64 | COFF / `execute_coff`, `go` |
| Windows | `ai_path_scout-windows-x64.exe` | x64 | Standalone, `main` |
| Windows | `ai_path_scout-managed.exe` | AnyCPU / .NET Framework 4.7.2 | Apollo `execute_assembly`, `Main` |
| macOS | `libai_path_scout.dylib` | universal (arm64/x86_64) | Poseidon `execute_library`, `bl_scout_run` |
| Linux | `libai_path_scout.so` | x64 | Poseidon `native_call`, `bl_scout_run` |

The Windows BOF, macOS dylib, and Linux `.so` are no-argument, unfiltered filesystem-triage snapshots. Native and managed Windows executables are the intentionally richer endpoint tier. Semantic content parsing remains an Analyze responsibility.

For Poseidon on macOS, run `execute_library` with `function_name` set to `bl_scout_run` and an empty `args` array.

## POSIX Usage

```text
ai_path_scout
```

Apollo usage:

```text
register_assembly ai_path_scout-managed.exe
execute_assembly -Assembly ai_path_scout-managed.exe
execute_assembly -Assembly ai_path_scout-managed.exe
```

## Build and Verification

Use the repository wrappers for the Windows/Linux matrix:

```powershell
.\blacklight-scout\build.ps1
```

```bash
./blacklight-scout/build.sh
```

Build `libai_path_scout.dylib` on Darwin with `make -C blacklight-scout release-macos`. See the canonical [release checklist](../../docs/RELEASE.md) for host-toolchain alternatives, matrix verification, safety gates, packaging, and publishing.
