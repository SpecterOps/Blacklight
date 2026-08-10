"""Offline Blacklight session analysis package."""

import sys

if sys.version_info < (3, 11):
    raise ImportError(
        "Blacklight requires Python 3.11 or newer "
        f"(found {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}). "
        "On macOS, `python3` is often Apple's 3.9 — run with `python3.11 -m blacklight ...` "
        "or install 3.11+ and reinstall with that interpreter (`python3.11 -m pip install -e .`)."
    )

from .analyze import (
    build_session_targeting_report,
    run_session_detail,
    run_session_high_value,
    run_session_targeting_report,
)
from .session_input import SessionInputDiscovery, SessionSource, discover_session_inputs
from .sessions import run_sessions_analysis

__all__ = [
    "build_session_targeting_report",
    "run_session_detail",
    "run_session_high_value",
    "run_session_targeting_report",
    "SessionInputDiscovery",
    "SessionSource",
    "discover_session_inputs",
    "run_sessions_analysis",
]
