# Codex state database inputs

Select `state_5.sqlite` and any available adjacent `-wal` and `-shm` files
together. Analysis copies this exact set to a temporary directory and reads
the copy; WAL transactions are included without changing the selected input.
Copy from a quiescent source or use a consistent acquisition snapshot because
ordinary file copies cannot guarantee consistency while a client is writing.

Local Codex discovery includes `state_5.sqlite` and backups whose names begin
with `state_5.sqlite.bak`, `.backup`, or `.corrupt`. Corruption is reported as
a parse failure; Blacklight does not repair these files. SQLite probing also
supports selected renamed databases when their supported schema identifies
another tool, but Codex state indexes retain their identifying filename.

The state index is inspected for table names and row counts only. No rollout
paths from its rows are followed. A database row does not prove its referenced
session file exists, and index rows never become recovered chat sessions.
Collect existing rollout JSONL or JSONL Zstandard files to recover chat data.

The upstream [Codex state corruption report](https://github.com/openai/codex/issues/27363)
documents that session rollouts and the state index can survive independently.
The synthetic SQLite tests cover WAL-only rows, unchanged source files,
corrupt backups, and a database row pointing to a nonexistent rollout.
