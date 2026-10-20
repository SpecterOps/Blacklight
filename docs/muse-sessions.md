# Muse Code durable events

Session Analysis reads selected Muse `session.jsonl` files, including the default
`.local/share/muse/sessions/YYYY/MM/DD/<id>/session.jsonl` layout. Use
`uv run --locked blacklight sessions local --tool muse_code` or pass an explicitly selected file
or directory. The session index, locks, sockets, and tool-output spill files are
not independently parsed as conversations.

The reader supports the observed schema-version-1 durable event envelope:
session metadata, accepted user text, started prompts, committed assistant
messages, tool calls, and textual tool results. A started prompt already present
in the accepted intent is not counted twice. Unknown envelope, payload, and run
event types are skipped. Unknown-only files never create synthetic sessions.
Newer retained-frame payloads are currently skipped, so reports may cover only
the recognized portion of a transcript.

Retention and deletion can remove local files. A missing file is not proof of
no prior session; this reader analyzes the artifacts that remain and does not
reconstruct deleted history. Fixtures cover disappearing files, future records,
prompt deduplication, and complete report integration.

Format evidence is the original version-pinned
[Muse adapter research](https://github.com/xhluca/session-migrate/blob/main/docs/muse-qwen-kimi-formats.md)
and its [native reader](https://github.com/xhluca/session-migrate/blob/main/src/session_migrate/formats/muse.py),
observed against Muse Code 0.2.1 build `b3170a534f`. This is a bounded format
implementation, not a claim of compatibility with every Muse release. No Muse
executable was launched for these changes.
