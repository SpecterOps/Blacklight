from __future__ import annotations

import shutil
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def sqlite_snapshot(path: Path) -> Iterator[sqlite3.Connection]:
    """Read a selected database and its exact sidecars without changing the input."""
    with tempfile.TemporaryDirectory(prefix="blacklight-sqlite-") as directory:
        copied = Path(directory) / path.name
        shutil.copy2(path, copied)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if sidecar.is_symlink():
                raise OSError(f"SQLite sidecar must not be a symbolic link: {sidecar}")
            if sidecar.is_file():
                shutil.copy2(sidecar, Path(str(copied) + suffix))
        with closing(sqlite3.connect(copied.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only = ON")
            yield connection
