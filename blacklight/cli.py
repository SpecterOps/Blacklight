from __future__ import annotations

import argparse
import json
from typing import Any

from .sessions import run_sessions_analysis, session_summary_lines


def _print_result(result: Any) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blacklight",
        description="Analyze downloaded AI-agent session artifacts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sessions = subparsers.add_parser(
        "sessions",
        help="Recursively discover and analyze session artifacts.",
    )
    sessions.add_argument("input_path")
    sessions.add_argument("--tool", choices=["codex", "claude", "cursor", "antigravity_cli"])
    sessions.add_argument("--output-directory")
    sessions.add_argument("--run-id")
    sessions.add_argument("--json", action="store_true", help="Print the machine-readable analysis summary.")
    sessions.add_argument("--max-files", type=int, default=10_000)
    sessions.add_argument(
        "--max-file-size",
        type=int,
        default=512 * 1024 * 1024,
        help="Maximum bytes read from any one artifact.",
    )
    sessions.add_argument("--include", action="append", default=[], metavar="GLOB")
    sessions.add_argument("--exclude", action="append", default=[], metavar="GLOB")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "sessions":
        result = run_sessions_analysis(
            args.input_path,
            tool=args.tool,
            output_directory=args.output_directory,
            run_id=args.run_id,
            max_files=args.max_files,
            max_file_size=args.max_file_size,
            includes=args.include,
            excludes=args.exclude,
        )
        if args.json:
            _print_result(result)
        else:
            print("\n".join(session_summary_lines(result)))
        return 0

    raise ValueError(f"Unknown command: {args.command}")
