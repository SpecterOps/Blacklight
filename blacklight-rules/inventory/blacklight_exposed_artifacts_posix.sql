WITH user_homes AS (
  SELECT username, directory
  FROM users
  WHERE directory LIKE '/%'
    AND directory NOT IN ('/', '/dev/null', '/nonexistent', '/var/empty')
),
targets(tool, family, relative_path) AS (
  VALUES
    ('codex', 'auth', '/.codex/auth.json'),
    ('codex', 'auth', '/.codex/.sandbox-secrets/sandbox_users.json'),
    ('codex', 'config', '/.codex/config.toml'),
    ('codex', 'rules', '/.codex/rules/default.rules'),
    ('codex', 'sandbox', '/.codex/.sandbox/setup_marker.json'),
    ('codex', 'sandbox', '/.codex/.sandbox/setup_error.json'),
    ('codex', 'sessions', '/.codex/session_index.jsonl'),
    ('claude_code', 'auth', '/.claude/.credentials.json'),
    ('claude_code', 'config', '/.claude/settings.json'),
    ('claude_code', 'config', '/.claude/.claude.json'),
    ('claude_code', 'config', '/.claude.json'),
    ('claude_code', 'mcp', '/.claude/mcp-needs-auth-cache.json'),
    ('claude_code', 'plugins', '/.claude/plugins'),
    ('cursor', 'config', '/.cursor/cli-config.json'),
    ('cursor', 'mcp', '/.cursor/mcp.json'),
    ('cursor', 'history', '/.cursor/prompt_history.json'),
    ('cursor', 'telemetry', '/.cursor/ai-tracking/ai-code-tracking.db'),
    ('antigravity_cli', 'config', '/.gemini/antigravity-cli/settings.json'),
    ('antigravity_cli', 'mcp', '/.gemini/antigravity-cli/mcp_config.json'),
    ('antigravity_cli', 'sessions', '/.gemini/antigravity-cli/conversation_summaries.db'),
    ('grok', 'config', '/.grok/config.toml'),
    ('grok', 'auth', '/.grok/auth.json'),
    ('grok', 'sessions', '/.grok/active_sessions.json'),
    ('grok', 'sessions', '/.grok/sessions/session_search.sqlite'),
    ('grok', 'workspace', '/.grok/memory-v2'),
    ('grok', 'plugins', '/.grok/installed-plugins'),
    ('grok', 'worktrees', '/.grok/worktrees.db')
)
SELECT
  targets.tool,
  targets.family,
  user_homes.username,
  file.path,
  file.uid,
  file.gid,
  file.mode,
  file.size,
  datetime(file.mtime, 'unixepoch') AS mtime_utc,
  CASE
    WHEN substr(file.mode, -1, 1) IN ('4', '5', '6', '7') THEN 'world_readable'
    WHEN substr(file.mode, -2, 1) IN ('4', '5', '6', '7') THEN 'group_readable'
    ELSE 'owner_only_or_unknown'
  END AS exposure_reason
FROM user_homes
CROSS JOIN targets
JOIN file ON file.path = user_homes.directory || targets.relative_path
WHERE substr(file.mode, -1, 1) IN ('4', '5', '6', '7')
   OR substr(file.mode, -2, 1) IN ('4', '5', '6', '7')
ORDER BY exposure_reason, targets.tool, file.path;
