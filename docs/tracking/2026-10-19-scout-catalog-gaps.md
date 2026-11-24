# Scout catalog: Devin/Kiro relocatable dirs and Claude Code PDF transcript change (Oct 2026)
Weekly matrix scan (Oct 19, 2026) found upstream on-disk changes that affect Scout coverage and session analysis.

## Devin
- [CLI 3000.11.92](https://docs.devin.ai/cli/changelog/stable) (Oct 14) adds `DEVIN_SESSIONS_DIR`, which moves the session history database to another directory.
- On hosts that set it, Scout's fixed Devin session path comes up empty.
- **Proposed:** have Scout check the env var (or at least flag it) before reporting Devin sessions absent. Also catalog `sessions.db` (+ `-wal`), `~/.config/devin/mcp_config.json`, and `*.log.gz` (logs gzipped after 48h); the matrix has no sessions family for Devin today.

## Kiro
- [CLI 2.31](https://kiro.dev/changelog/cli/2-31/) (Oct 13): `KIRO_HOME` now covers all V3 config and state, so V3 files can live outside Scout's home-relative Kiro paths. `KIRO_SESSIONS_DIR` can also relocate sessions.
- [V3 becomes the default](https://kiro.dev/blog/cli-3/) with CLI 3.0 by end of October; expect layout to shift again.
- [2.29](https://kiro.dev/changelog/cli/2-29/) (Oct 9) added cross-session memories at `~/.kiro/memories/`, which is not in the catalog.
- **Proposed:** honor/flag `KIRO_HOME` and `KIRO_SESSIONS_DIR`, add `~/.kiro/memories`, and re-check paths after 3.0 ships.

## Claude Code
- [2.1.299](https://github.com/anthropics/claude-code/releases) (Oct 14): @-mentioned PDFs no longer have their bytes saved in the session transcript. JSONL format is unchanged.
- **Proposed:** note in Session Analysis docs that newer transcripts won't contain PDF content, so absence isn't evidence the PDF wasn't read.

## No on-disk impact found this week
Codex (0.163, 0.164 alphas), OpenCode (1.19.x), Antigravity (1.4.x), Grok Build (1.0.62), Muse Code (1.4.10), Cursor CLI, Strands.

All of this comes from upstream changelogs and has not been checked on real hosts.
