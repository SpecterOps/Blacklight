#!/usr/bin/env python3
"""Update or check the release version copies in the repository."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\Z")


def read_text(path: Path) -> str:
    with path.open(encoding="utf-8", newline="") as stream:
        return stream.read()


def write_text(path: Path, value: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write(value)


def project_version(root: Path) -> str:
    text = read_text(root / "pyproject.toml")
    match = re.search(r'(?ms)^\[project\]\s*.*?^version\s*=\s*"([^"]+)"', text)
    if not match:
        raise ValueError("Could not find [project].version in pyproject.toml")
    return match.group(1)


def _replace_one(path: Path, pattern: str, replacement: str, label: str) -> str:
    text = read_text(path)
    result, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"Could not find {label} in {path}")
    return result


def expected_files(root: Path, version: str) -> dict[Path, str]:
    native = root / "blacklight-scout/native/ai_path_scout_windows.c"
    managed = root / "blacklight-scout/managed/Program.cs"
    csproj = root / "blacklight-scout/managed/ai_path_scout-managed.csproj"
    release_index = root / "blacklight-scout/releases/metadata.json"
    bundle = root / "blacklight-scout/releases/ai_path_scout/metadata.json"

    project = _replace_one(
        root / "pyproject.toml",
        r'(?m)^(version\s*=\s*")[^"]+("\s*)\r?$',
        rf'\g<1>{version}\g<2>',
        "project version",
    )
    native_text = _replace_one(native, r'(?m)^(#define BL_SCOUT_VERSION ")[^"]+("\r?)$', rf'\g<1>{version}\g<2>', "native Scout version")
    managed_text = _replace_one(managed, r'(?m)^(\s*private const string Version = ")[^"]+(";\r?)$', rf'\g<1>{version}\g<2>', "managed Scout version")
    csproj_text = _replace_one(csproj, r'(?m)^(\s*<Version>)[^<]+(</Version>\r?)$', rf'\g<1>{version}\g<2>', "managed project version")

    def replace_json_version(path: Path, pattern: str, label: str) -> str:
        return _replace_one(path, pattern, rf'\g<1>{version}\g<2>', label)

    return {
        root / "pyproject.toml": project,
        native: native_text,
        managed: managed_text,
        csproj: csproj_text,
        release_index: replace_json_version(release_index, r'(?m)("version"\s*:\s*")[^"]+("\s*,?)', "release index version"),
        bundle: replace_json_version(bundle, r'(?m)("version"\s*:\s*")[^"]+("\s*,?)', "bundle version"),
    }


def expected_changelog(root: Path, version: str, today: date) -> str:
    path = root / "CHANGELOG.md"
    text = read_text(path)
    dated_heading = re.compile(rf"(?m)^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}[ \t]*\r?$")
    if dated_heading.search(text):
        return text
    existing_heading = re.compile(rf"(?m)^## \[{re.escape(version)}\][ \t]*\r?$")
    if existing_heading.search(text):
        return existing_heading.sub(f"## [{version}] - {today.isoformat()}", text, count=1)
    marker = re.search(r"(?m)^## \[Unreleased\][ \t]*(?=\r?$)", text)
    if not marker:
        raise ValueError("Could not find ## [Unreleased] in CHANGELOG.md")
    newline = "\r\n" if "\r\n" in text else "\n"
    insert_at = marker.end()
    insertion = f"{newline}## [{version}] - {today.isoformat()}{newline}"
    return text[:insert_at] + insertion + text[insert_at:]


def check(root: Path, version: str, today: date | None = None) -> list[str]:
    errors: list[str] = []
    try:
        if project_version(root) != version:
            errors.append(f"pyproject.toml: expected canonical version {version}")
        for path, expected in expected_files(root, version).items():
            if read_text(path) != expected:
                errors.append(f"{path.relative_to(root)}: version does not match {version}")
        changelog = read_text(root / "CHANGELOG.md")
        if not re.search(rf"(?m)^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}\s*$", changelog):
            errors.append(f"CHANGELOG.md: missing dated heading for {version}")
        lock = read_text(root / "uv.lock")
        lock_data = tomllib.loads(lock)
        project_name = tomllib.loads(read_text(root / "pyproject.toml"))["project"]["name"]
        if not any(p["name"] == project_name and p["version"] == version for p in lock_data["package"]):
            errors.append(f"uv.lock: package {project_name} does not match {version}")
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        errors.append(str(exc))
    return errors


def update(root: Path, version: str, today: date | None = None) -> None:
    today = today or date.today()
    files = expected_files(root, version)
    changelog = expected_changelog(root, version, today)
    for path, text in files.items():
        write_text(path, text)
    write_text(root / "CHANGELOG.md", changelog)
    subprocess.run(["uv", "lock"], cwd=root, check=True)
    errors = check(root, version, today)
    if errors:
        raise ValueError("Version update did not produce a consistent release:\n" + "\n".join(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="release version to write; omit for --check")
    parser.add_argument("--check", action="store_true", help="check all release version copies without writing")
    args = parser.parse_args(argv)
    try:
        if args.check:
            if args.version:
                parser.error("--check does not take a version argument")
            version = project_version(ROOT)
            errors = check(ROOT, version)
            if errors:
                print("\n".join(errors), file=sys.stderr)
                return 1
            print(f"All release version copies match {version}.")
            return 0
        if not args.version or not VERSION_RE.fullmatch(args.version):
            parser.error("provide a version in MAJOR.MINOR.PATCH form")
        if args.version == project_version(ROOT):
            parser.error(f"{args.version} is already the canonical project version")
        update(ROOT, args.version)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"set_version: {exc}", file=sys.stderr)
        return 1
    print(f"Updated release version to {args.version}; add release notes to CHANGELOG.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
