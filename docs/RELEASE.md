# Release Blacklight Scout

## Prepare

- Choose a release version and update `pyproject.toml`, native and managed executable versions, both Scout release metadata files, and `CHANGELOG.md` together.
- Move completed Unreleased notes into a dated release heading before tagging.
- Regenerate the catalog and commit any source or generated documentation changes:

```powershell
py -3 blacklight-scout/catalog/generate_targets.py; git diff --check
```

## Validate

Run the Python suite on a host that permits fixture symlinks:

```powershell
py -3 -m unittest discover -s blacklight/tests -v
```

Run the generator a second time and require no changes to the generated C table or `docs/matrix.md`. The managed `GeneratedTargets.cs` is generated and ignored by Git; build it from the same catalogs.

Build the Windows BOF, native executable, managed executable, and Linux shared library with Docker:

```powershell
.\blacklight-scout\build.ps1
```

Run `bash blacklight-scout/native/smoke_test.sh` on Linux and the native/managed executable fixture tests on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File blacklight-scout/tests/exe_triage_smoke.ps1
```

On macOS, build the universal dylib with `make -C blacklight-scout release-macos`. A Windows/Linux build does not validate the macOS artifact.

When all platform artifacts are available, verify the complete matrix:

```powershell
py -3 blacklight-scout/releases/verify_matrix.py --platform all
```

Require all five artifacts: `ai_path_scout.x64.o`, `ai_path_scout-windows-x64.exe`, `ai_path_scout-managed.exe`, `libai_path_scout.so`, and universal `libai_path_scout.dylib`. Validate metadata, body-free output, tool filters and aliases, and existing fixture smoke tests. Record unavailable platform checks explicitly; they remain release gates.

## Publish

Only tag a validated release commit. Push the selected `v<version>` tag to start `.github/workflows/release.yml`; the workflow rebuilds and verifies artifacts on Windows, Linux, and macOS.

Confirm the completed GitHub Release contains all five binaries, release metadata, representative output, and `SHA256SUMS.txt`. Verify checksums and workflow success before announcing the release. Branch integration alone does not authorize a release tag or publication.
