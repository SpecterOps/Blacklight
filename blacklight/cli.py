from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .progress import TerminalProgress
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
        help="Analyze local agent session roots or a supplied path.",
    )
    sessions.add_argument(
        "input_path",
        nargs="?",
        default="local",
        metavar="INPUT_PATH",
        help="Directory or file to analyze; 'local' (also the default) selects known agent session roots in the current user's home.",
    )
    sessions.add_argument("--tool", choices=["codex", "claude", "cursor", "antigravity_cli", "grok", "grok-cli", "opencode", "muse_code"],
                          help="Select one agent root in local mode; detection hint for an explicit path.")
    sessions.add_argument("--output-directory")
    sessions.add_argument("--run-id")
    sessions.add_argument("--no-progress", action="store_true", help="Disable the interactive progress display.")
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
        input_path = Path.home() if args.input_path == "local" else args.input_path
        with TerminalProgress(enabled=not args.no_progress) as progress:
            result = run_sessions_analysis(
                input_path,
                tool=args.tool,
                output_directory=args.output_directory,
                run_id=args.run_id,
                max_files=args.max_files,
                max_file_size=args.max_file_size,
                includes=args.include,
                excludes=args.exclude,
                progress_callback=progress.update if progress.enabled else None,
                local_mode=args.input_path == "local",
            )
        if args.json:
            _print_result(result)
        else:
            print("\n".join(session_summary_lines(result)))
        return 0

    raise ValueError(f"Unknown command: {args.command}")
