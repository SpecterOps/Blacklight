# OpenCode SQLite sessions

Session Analysis reads both V1 `session`/`message`/`part` and V2
`session_v2`/`session_message` from a selected `opencode.db`. Both families can
coexist. Session identities include a `v1:` or `v2:` prefix so equal IDs from
different generations remain distinguishable. Text, reasoning text, and tool
inputs/results contribute to the existing redacted metrics and indicators.

Preserve exact adjacent `opencode.db-wal` and `opencode.db-shm` files during
consistent collection. The database can contain credentials; analysis queries
session tables only and does not query credential values. Schema probing reads
table and column names. Unsupported schemas or malformed JSON payloads are
reported as parsing failures rather than repaired or migrated.

Use `uv run --locked blacklight sessions /selected/opencode.db --tool opencode`, or select the
default local root with `uv run --locked blacklight sessions local --tool opencode`.

Implementation evidence is static upstream source:
[V2 SQLite schema](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/session/sql.ts)
and [session message schema](https://github.com/anomalyco/opencode/blob/dev/packages/schema/src/session-message.ts).
No OpenCode executable was launched to implement or validate this support.
Synthetic tests cover coexistence, WAL-only content, credentials excluded from
reports, and malformed payload failures.
