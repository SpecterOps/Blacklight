"""Optional analysis telemetry and a dependency-free terminal renderer."""
from __future__ import annotations

import shutil
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, TextIO, TypeVar


@dataclass(frozen=True)
class ProgressEvent:
    phase: str
    completed: int = 0
    total: int | None = None


ProgressCallback = Callable[[ProgressEvent], None]
T = TypeVar("T")
_SPINNER = "|/-\\"


class AnalysisProgress:
    def __init__(self, callback: ProgressCallback | None = None) -> None:
        self.callback = callback
        self.event = ProgressEvent("Discovering files")

    def start(self, phase: str, total: int | None = None) -> None:
        self.event = ProgressEvent(phase, 0, total)
        self._emit()

    def advance(self, count: int = 1) -> None:
        self.event = ProgressEvent(self.event.phase, self.event.completed + count, self.event.total)
        self._emit()

    def _emit(self) -> None:
        if self.callback is not None:
            self.callback(self.event)

    def items(self, values: Iterable[T]) -> Iterator[T]:
        for value in values:
            yield value
            self.advance()


class TerminalProgress:
    """Only the refresh thread writes while analysis is running."""

    def __init__(self, *, enabled: bool = True, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = enabled and self.stream.isatty()
        self._event = ProgressEvent("Discovering files")
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = 0.0
        self._frame = 0
        self._width = 0

    def update(self, event: ProgressEvent) -> None:
        with self._lock:
            self._event = event

    def __enter__(self) -> TerminalProgress:
        if self.enabled:
            self._started = time.monotonic()
            self._render()
            self._thread = threading.Thread(target=self._refresh, name="blacklight-progress", daemon=True)
            self._thread.start()
        return self

    def _refresh(self) -> None:
        while not self._stop.wait(0.1):
            self._render()

    def _render(self, status: str | None = None) -> None:
        with self._lock:
            event = self._event
        elapsed = int(time.monotonic() - self._started)
        timer = f"elapsed {elapsed // 60:02d}:{elapsed % 60:02d}"
        spinner = _SPINNER[self._frame % len(_SPINNER)]
        if status is not None:
            line = f"{status}  {timer}"
        elif event.total is None:
            line = f"{event.phase} {spinner}  {timer}"
        else:
            fraction = event.completed / event.total if event.total else 1.0
            filled = min(20, int(fraction * 20))
            line = (f"{event.phase} [{'#' * filled}{'-' * (20 - filled)}] "
                    f"{fraction:.0%}  {event.completed}/{event.total} files  {spinner}  {timer}")
        self._frame += 1
        # Reserve the last column to avoid wrapping, including on Windows consoles.
        width = max(1, shutil.get_terminal_size(fallback=(100, 24)).columns - 1)
        if len(line) > width and status is None:
            counts = f" {event.completed}/{event.total}" if event.total is not None else ""
            line = f"{event.phase} {spinner}{counts} {timer}"
        line = line[:width]
        self.stream.write("\r" + line + " " * max(0, min(self._width, width) - len(line)))
        self.stream.flush()
        self._width = len(line)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.enabled:
            self._stop.set()
            if self._thread is not None:
                self._thread.join()
            status = "Complete" if exc_type is None else ("Interrupted" if exc_type is KeyboardInterrupt else "Failed")
            self._render(status)
            self.stream.write("\n")
            self.stream.flush()
