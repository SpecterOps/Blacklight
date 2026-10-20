# Grok memory inventory validation

Validated on a local installation on 2026-10-17 using directory entries only:
`~/.grok/memory-v2` exists with `global` and `workspaces` descendants.
Observed artifact names include `MEMORY.md`, `index.sqlite`,
`memory_state.sqlite`, and its SQLite sidecars. No memory bodies or database
values were read for this validation.

The existing `grok.memory_v2` catalog entry already assesses this directory as
workspace metadata on all three platforms. Memory content remains deferred;
local session analysis selects chats under `.grok/sessions` only. The synthetic
regression in `test_grok_memory_boundary.py` verifies that memory files are
never opened by local session discovery. This validation establishes the path
on one installation; it does not assert a universal memory schema.
