#!/usr/bin/env python3
"""Generate Scout target tables from blacklight-scout/catalog/targets.json."""

from __future__ import annotations

import json
from pathlib import Path

CATALOG_DIR = Path(__file__).resolve().parent
TARGETS_JSON = CATALOG_DIR / "targets.json"
C_HEADER_OUT = CATALOG_DIR / "static_targets_generated.h"
CS_TARGETS_OUT = CATALOG_DIR.parent / "managed" / "GeneratedTargets.cs"


def load_catalog() -> dict:
    return json.loads(TARGETS_JSON.read_text(encoding="utf-8"))


def normalize_pattern_for_python(pattern: str) -> str:
    return pattern.replace("\\", "/")


def pattern_to_c_windows(pattern: str) -> str:
    normalized = normalize_pattern_for_python(pattern)
    escaped = normalized.replace("\\", "\\\\")
    return f'L"{escaped}"'


def pattern_to_c_posix(pattern: str) -> str:
    return f'"{normalize_pattern_for_python(pattern)}"'


def render_c_header(catalog: dict) -> str:
    lines = [
        "/* Auto-generated from blacklight-scout/catalog/targets.json. Do not edit by hand. */",
        "#ifndef BLACKLIGHT_STATIC_TARGETS_GENERATED_H",
        "#define BLACKLIGHT_STATIC_TARGETS_GENERATED_H",
        "",
        '#include "ai_path_scout_core.h"',
        "",
    ]

    def append_target_table(targets: list[dict], *, windows: bool) -> None:
        lines.append("static const bl_path_target_t BL_STATIC_TARGETS[] = {")
        for target in targets:
            pattern = pattern_to_c_windows(target["pattern"]) if windows else pattern_to_c_posix(target["pattern"])
            lines.append(f'    {{ "{target["tool"]}", "{target["family"]}", {pattern} }},')
        lines.append("};")

    windows_targets = catalog["platforms"]["windows"]["targets"]
    darwin_targets = catalog["platforms"]["darwin"]["targets"]
    linux_targets = catalog["platforms"]["linux"]["targets"]

    lines.append("#ifdef BLACKLIGHT_SCOUT_WINDOWS")
    append_target_table(windows_targets, windows=True)
    lines.append("#elif defined(__APPLE__)")
    append_target_table(darwin_targets, windows=False)
    lines.append("#else")
    append_target_table(linux_targets, windows=False)
    lines.append("#endif")
    lines.append("")
    lines.append("#define BL_STATIC_TARGETS_COUNT (sizeof(BL_STATIC_TARGETS) / sizeof(BL_STATIC_TARGETS[0]))")
    lines.append("")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def csharp_string(value: str) -> str:
    return (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def render_csharp_targets(catalog: dict) -> str:
    windows_targets = catalog["platforms"]["windows"]["targets"]
    lines = [
        "// Auto-generated from blacklight-scout/catalog/targets.json. Do not edit by hand.",
        "namespace Blacklight.Scout.Managed",
        "{",
        "    internal static class GeneratedTargets",
        "    {",
        "        internal static readonly Target[] Windows = new Target[]",
        "        {",
    ]
    for target in windows_targets:
        lines.append(
            '            new Target("{tool}", "{family}", "{pattern}"),'.format(
                tool=csharp_string(target["tool"]),
                family=csharp_string(target["family"]),
                pattern=csharp_string(target["pattern"]),
            )
        )
    lines.extend(
        [
            "        };",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    catalog = load_catalog()
    C_HEADER_OUT.write_text(render_c_header(catalog), encoding="utf-8")
    CS_TARGETS_OUT.parent.mkdir(parents=True, exist_ok=True)
    CS_TARGETS_OUT.write_text(render_csharp_targets(catalog), encoding="utf-8")
    print(f"Wrote {C_HEADER_OUT}")
    print(f"Wrote {CS_TARGETS_OUT}")


if __name__ == "__main__":
    main()
