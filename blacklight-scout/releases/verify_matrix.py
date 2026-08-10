#!/usr/bin/env python3
"""Verify the Blacklight Scout release artifact matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_OBJECTS = {
    "ai_path_scout.x64.o",
    "ai_path_scout-windows-x64.exe",
    "ai_path_scout-managed.exe",
    "libai_path_scout.dylib",
    "libai_path_scout.so",
}

EXPECTED_BY_PLATFORM = {
    "windows": {
        "out/build/scout/ai_path_scout.x64.o",
        "out/build/scout/ai_path_scout-windows-x64.exe",
    },
    "macos": {
        "out/build/scout/libai_path_scout.dylib",
    },
    "linux": {
        "out/build/scout/libai_path_scout.so",
        "out/build/scout/ai_path_scout-managed.exe",
    },
    "local": {
        "out/build/scout/ai_path_scout.x64.o",
        "out/build/scout/ai_path_scout-windows-x64.exe",
        "out/build/scout/libai_path_scout.so",
        "out/build/scout/ai_path_scout-managed.exe",
    },
    "all": {
        "out/build/scout/ai_path_scout.x64.o",
        "out/build/scout/ai_path_scout-windows-x64.exe",
        "out/build/scout/ai_path_scout-managed.exe",
        "out/build/scout/libai_path_scout.dylib",
        "out/build/scout/libai_path_scout.so",
    },
}

RETIRED_OBJECTS = {
    "ai_path_scout-macos",
    "ai_path_scout-linux-x64",
}

METADATA_PATHS = [
    Path("blacklight-scout/releases/metadata.json"),
    Path("blacklight-scout/releases/ai_path_scout/metadata.json"),
]


def _load_artifacts(path: Path) -> list[dict[str, object]]:
    data = json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))
    if "artifacts" in data:
        return list(data["artifacts"])
    return list(data["bundles"][0]["artifacts"])


def verify_metadata() -> None:
    for path in METADATA_PATHS:
        artifacts = _load_artifacts(path)
        objects = {str(artifact["object"]) for artifact in artifacts}
        if objects != EXPECTED_OBJECTS:
            raise SystemExit(f"{path}: expected {sorted(EXPECTED_OBJECTS)}, got {sorted(objects)}")
        retired = objects & RETIRED_OBJECTS
        if retired:
            raise SystemExit(f"{path}: retired artifacts still present: {sorted(retired)}")
        missing_paths = [artifact["object"] for artifact in artifacts if not artifact.get("path")]
        if missing_paths:
            raise SystemExit(f"{path}: artifacts missing path fields: {missing_paths}")
        print(f"{path}: metadata ok")


def verify_files(platform: str) -> None:
    expected_paths = EXPECTED_BY_PLATFORM[platform]
    for relative in sorted(expected_paths):
        path = REPO_ROOT / relative
        if not path.is_file():
            raise SystemExit(f"missing artifact: {relative}")
        if path.stat().st_size <= 0:
            raise SystemExit(f"empty artifact: {relative}")
        print(f"{relative}: {path.stat().st_size} bytes")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=sorted(EXPECTED_BY_PLATFORM),
        help="Require artifact files for this platform/mode. Use local for the Windows/Linux artifacts buildable from WSL.",
    )
    args = parser.parse_args()
    verify_metadata()
    if args.platform:
        verify_files(args.platform)


if __name__ == "__main__":
    main()
