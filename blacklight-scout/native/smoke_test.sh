#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
SMOKE_BIN="${BUILD_DIR:-$REPO_ROOT/out/build/scout}/ai_path_scout_smoke"
cd "$ROOT"

make smoke

fixture_home="$(mktemp -d)"
trap 'rm -rf "$fixture_home"' EXIT
mkdir -p \
  "$fixture_home/.codex/.sandbox" \
  "$fixture_home/.codex/rules" \
  "$fixture_home/.codex/sessions" \
  "$fixture_home/.codex/nested" \
  "$fixture_home/.claude/plugins" \
  "$fixture_home/.claude/projects/project with space" \
  "$fixture_home/.cursor/agents" \
  "$fixture_home/.cursor/plugins" \
  "$fixture_home/.cursor/plans" \
  "$fixture_home/.cursor/chats/workspace/session" \
  "$fixture_home/.cursor/projects/workspace/agent-transcripts/cursor-session" \
  "$fixture_home/.grok/sessions/workspace/session"
touch \
  "$fixture_home/.codex/auth.json" \
  "$fixture_home/.codex/config.toml" \
  "$fixture_home/.codex/.sandbox/setup_marker.json" \
  "$fixture_home/.claude/.credentials.json"
printf '%s' 'BLACKLIGHT_SQLITE_CONTENT_SHOULD_NOT_APPEAR' > "$fixture_home/.codex/logs_2.sqlite"
truncate -s 22 "$fixture_home/.codex/logs_10.sqlite"
truncate -s 33 "$fixture_home/.codex/logs_99.sqlite"
truncate -s 25 "$fixture_home/.codex/thread_history_2.sqlite"
truncate -s 35 "$fixture_home/.codex/thread_history_7.sqlite"
long_version_suffix=99999999999999999999999999999999999999999999999999999999999999999999999999999999
truncate -s 36 "$fixture_home/.codex/thread_history_$long_version_suffix.sqlite"
truncate -s 45 "$fixture_home/.codex/state_5.sqlite"
truncate -s 55 "$fixture_home/.codex/memories_1.sqlite"
touch -t 202607020000 \
  "$fixture_home/.codex/logs_2.sqlite" \
  "$fixture_home/.codex/logs_10.sqlite" \
  "$fixture_home/.codex/thread_history_2.sqlite" \
  "$fixture_home/.codex/thread_history_7.sqlite" \
  "$fixture_home/.codex/thread_history_$long_version_suffix.sqlite"
touch -t 202607010000 "$fixture_home/.codex/logs_99.sqlite"
touch -t 202607030000 "$fixture_home/.codex/state_5.sqlite" "$fixture_home/.codex/memories_1.sqlite"
touch "$fixture_home/.codex/logs_100.sqlite-wal" "$fixture_home/.codex/state.sqlite" "$fixture_home/.codex/memories_abc.sqlite"
touch "$fixture_home/.codex/nested/goals_7.sqlite"
ln -s "$fixture_home/.codex/config.toml" "$fixture_home/.codex/goals_9.sqlite"
touch \
  "$fixture_home/.grok/auth.json" \
  "$fixture_home/.grok/config.toml" \
  "$fixture_home/.grok/active_sessions.json" \
  "$fixture_home/.grok/sessions/session_search.sqlite"
printf '%s\n' 'prefix_rule(pattern=["git", "diff"], decision="deny")' > "$fixture_home/.codex/rules/project.rules"
printf '%s\n' '{}' > "$fixture_home/.claude/projects/project with space/.mcp.json"
printf '%s\n' '{}' > "$fixture_home/.cursor/projects/workspace/.mcp.json"
printf '%s\n' '{}' > "$fixture_home/.cursor/mcp.json"
printf '%s\n' '# plan metadata fixture' > "$fixture_home/.cursor/plans/sample.plan.md"
touch -t 202607010000 "$fixture_home/.cursor/plans/sample.plan.md"
for i in $(seq 1 7); do
  plan_number="$(printf '%02d' "$i")"
  printf '%s\n' '# plan metadata fixture' > "$fixture_home/.cursor/plans/plan-$plan_number.plan.md"
  touch -t "20260720${plan_number}00" "$fixture_home/.cursor/plans/plan-$plan_number.plan.md"
done
truncate -s 100 "$fixture_home/.codex/sessions/small.jsonl"
truncate -s 200 "$fixture_home/.codex/sessions/medium.jsonl"
truncate -s 300 "$fixture_home/.codex/sessions/large.jsonl"
truncate -s 50 "$fixture_home/.codex/sessions/excluded-fourth.jsonl"
touch -t 202607040000 "$fixture_home/.codex/sessions/small.jsonl"
touch -t 202607030000 "$fixture_home/.codex/sessions/medium.jsonl"
touch -t 202607020000 "$fixture_home/.codex/sessions/large.jsonl"
touch -t 202607010000 "$fixture_home/.codex/sessions/excluded-fourth.jsonl"
truncate -s 500 "$fixture_home/.claude/projects/project with space/claude-session.jsonl"
truncate -s 400 "$fixture_home/.cursor/chats/workspace/session/store.db"
truncate -s 600 "$fixture_home/.cursor/projects/workspace/agent-transcripts/cursor-session/cursor-session.jsonl"
truncate -s 700 "$fixture_home/.grok/sessions/workspace/session/updates.jsonl"
truncate -s 5000 "$fixture_home/not-a-session.jsonl"
ln -s "$fixture_home/not-a-session.jsonl" "$fixture_home/.codex/sessions/linked.jsonl"

output="$(HOME="$fixture_home" "$SMOKE_BIN")"
echo "$output" | grep -q $'^\[i\] Blacklight endpoint assessment' || {
  echo "smoke test failed: default run did not emit collection-first triage" >&2
  exit 1
}
echo "$output" | grep -Eq 'BLACKLIGHT_(PATH|TRIAGE|SELECT)' && {
  echo "smoke test failed: default run emitted a retired machine record" >&2
  exit 1
}
for dynamic_path in \
  "$fixture_home/.codex/rules/project.rules" \
  "$fixture_home/.claude/projects/project with space/.mcp.json" \
  "$fixture_home/.cursor/projects/workspace/.mcp.json"; do
  echo "$output" | grep -Fq "$dynamic_path" || {
    echo "smoke test failed: missing dynamically discovered path $dynamic_path" >&2
    exit 1
  }
done
for grok_path in \
  "$fixture_home/.grok/auth.json" \
  "$fixture_home/.grok/config.toml" \
  "$fixture_home/.grok/sessions/session_search.sqlite" \
  "$fixture_home/.grok/sessions/workspace/session/updates.jsonl"; do
  echo "$output" | grep -Fq "$grok_path" || {
    echo "smoke test failed: missing Grok reconnaissance path $grok_path" >&2
    exit 1
  }
done

echo "$output" | grep -Fq '[i] CODEX SQLITE DATABASES' || {
  echo "smoke test failed: Codex SQLite section heading was missing" >&2
  exit 1
}
summary_line="$(echo "$output" | grep -n '^\[i\] ASSESSMENT SUMMARY$' | head -n1 | cut -d: -f1)"
database_line="$(echo "$output" | grep -n '^\[i\] CODEX SQLITE DATABASES$' | head -n1 | cut -d: -f1)"
first_collection_line="$(echo "$output" | grep -n '^\[i\] Collect first:' | head -n1 | cut -d: -f1)"
[ -n "$summary_line" ] && [ -n "$database_line" ] && [ -n "$first_collection_line" ] && \
  [ "$summary_line" -lt "$database_line" ] && [ "$database_line" -lt "$first_collection_line" ] || {
  echo "smoke test failed: Codex SQLite section was not between assessment summary and collection sections" >&2
  exit 1
}
echo "$output" | grep -Fq '    logs: present (3 versions) | newest observed 22 B | modified ' || {
  echo "smoke test failed: logs family did not use mtime then numeric suffix to select the newest version" >&2
  exit 1
}
echo "$output" | grep -Fxq "        $fixture_home/.codex/logs_10.sqlite" || {
  echo "smoke test failed: logs newest path was not on its own indented line" >&2
  exit 1
}
echo "$output" | grep -Fq '    thread_history: present (3 versions) | newest observed 36 B | modified ' || {
  echo "smoke test failed: thread_history numeric suffix tie-break did not handle a large version number" >&2
  exit 1
}
echo "$output" | grep -Fxq "        $fixture_home/.codex/thread_history_$long_version_suffix.sqlite" || {
  echo "smoke test failed: large thread_history version was not selected" >&2
  exit 1
}
echo "$output" | grep -Fq '    state: present (1 version) | newest observed 45 B | modified ' || {
  echo "smoke test failed: state family metadata was missing" >&2
  exit 1
}
echo "$output" | grep -Fxq "        $fixture_home/.codex/state_5.sqlite" || {
  echo "smoke test failed: state newest path was missing" >&2
  exit 1
}
echo "$output" | grep -Fq '    memories: present (1 version) | newest observed 55 B | modified ' || {
  echo "smoke test failed: memories family metadata was missing" >&2
  exit 1
}
echo "$output" | grep -Fxq "        $fixture_home/.codex/memories_1.sqlite" || {
  echo "smoke test failed: memories newest path was missing" >&2
  exit 1
}
echo "$output" | grep -Fq '    goals: absent (0 versions)' || {
  echo "smoke test failed: sidecar, nested, or symlink goals candidates were counted" >&2
  exit 1
}
echo "$output" | grep -Eq '\| modified [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' || {
  echo "smoke test failed: database modification time was not emitted in UTC" >&2
  exit 1
}
echo "$output" | grep -Fq 'BLACKLIGHT_SQLITE_CONTENT_SHOULD_NOT_APPEAR' && {
  echo "smoke test failed: database content appeared in metadata-only output" >&2
  exit 1
}
for excluded_db_path in \
  "$fixture_home/.codex/logs_100.sqlite-wal" \
  "$fixture_home/.codex/nested/goals_7.sqlite" \
  "$fixture_home/.codex/goals_9.sqlite"; do
  echo "$output" | grep -Fq "$excluded_db_path" && {
    echo "smoke test failed: excluded SQLite candidate appeared in output: $excluded_db_path" >&2
    exit 1
  }
done

missing_root_home="$(mktemp -d)"
missing_root_output="$(HOME="$missing_root_home" "$SMOKE_BIN")"
rm -rf "$missing_root_home"
for family in logs thread_history state memories goals; do
  echo "$missing_root_output" | grep -Fq "    $family: absent (0 versions)" || {
    echo "smoke test failed: missing Codex root did not report $family as absent" >&2
    exit 1
  }
done

unavailable_root_home="$(mktemp -d)"
touch "$unavailable_root_home/.codex"
unavailable_root_output="$(HOME="$unavailable_root_home" "$SMOKE_BIN")"
rm -rf "$unavailable_root_home"
for family in logs thread_history state memories goals; do
  echo "$unavailable_root_output" | grep -Fq "    $family: unknown (Codex root unavailable)" || {
    echo "smoke test failed: unavailable Codex root was reported as absent for $family" >&2
    exit 1
  }
done
echo "$unavailable_root_output" | grep -Fq '[!]   Discovery status:     PARTIAL' || {
  echo "smoke test failed: unavailable Codex root did not mark overall discovery partial" >&2
  exit 1
}

plan_preview_count="$(echo "$output" | grep -Ec "^\[i\]       $fixture_home/.cursor/plans(/|$)")"
[ "$plan_preview_count" -eq 6 ] || {
  echo "smoke test failed: expected the Cursor plans directory plus five plan previews" >&2
  exit 1
}
echo "$output" | grep -Fq '[i]       ... 3 additional plan artifacts omitted' || {
  echo "smoke test failed: Cursor plan preview did not report omitted artifacts" >&2
  exit 1
}
for recent_plan in plan-03.plan.md plan-04.plan.md plan-05.plan.md plan-06.plan.md plan-07.plan.md; do
  echo "$output" | grep -Fq "$fixture_home/.cursor/plans/$recent_plan" || {
    echo "smoke test failed: Cursor plan preview omitted a recent plan: $recent_plan" >&2
    exit 1
  }
done
for old_plan in sample.plan.md plan-01.plan.md plan-02.plan.md; do
  echo "$output" | grep -Fq "$fixture_home/.cursor/plans/$old_plan" && {
    echo "smoke test failed: Cursor plan preview included an older plan: $old_plan" >&2
    exit 1
  }
done

unsafe_home="$(mktemp -d)"
mkdir -p "$unsafe_home/.codex/sessions"
unsafe_name=$'\033[2Jline\n[+] forged.jsonl'
truncate -s 1 "$unsafe_home/.codex/sessions/$unsafe_name"
unsafe_output="$(HOME="$unsafe_home" "$SMOKE_BIN")"
rm -rf "$unsafe_home"
printf '%s' "$unsafe_output" | LC_ALL=C grep -Fq $'\033' && {
  echo "smoke test failed: emitted a terminal-control byte from a path" >&2
  exit 1
}
printf '%s' "$unsafe_output" | grep -Fq '\x1b[2Jline\n[+] forged.jsonl' || {
  echo "smoke test failed: did not escape control bytes in a path" >&2
  exit 1
}

ignored_args_output="$(HOME="$fixture_home" "$SMOKE_BIN" --triage --filter codex --jsonl)"
[ "$output" = "$ignored_args_output" ] || {
  echo "smoke test failed: supplied arguments changed fixed triage output" >&2
  exit 1
}
echo "$output" | grep -q $'^\[i\] Operator view' && {
  echo "smoke test failed: fixed triage emitted removed operator header" >&2
  exit 1
}
echo "$output" | grep -q $'^\[i\] PRIORITIZED SESSION ARTIFACTS (newest first)$' || {
  echo "smoke test failed: human triage did not emit top session files" >&2
  exit 1
}
top_line="$(echo "$output" | grep -n '^\[i\] PRIORITIZED SESSION ARTIFACTS (newest first)$' | head -n1 | cut -d: -f1)"
session_line="$(echo "$output" | grep -n '^\[i\] Session activity (collect selectively)$' | head -n1 | cut -d: -f1)"
[ -n "$top_line" ] && [ -n "$session_line" ] && [ "$top_line" -lt "$session_line" ] || {
  echo "smoke test failed: top session files did not precede session activity" >&2
  exit 1
}
echo "$output" | grep -E '^\[i\]   \[3\].*largest=' && {
  echo "smoke test failed: session activity still prints catalog largest=" >&2
  exit 1
}
for expected in '600 B' '500 B' '100 B'; do
  echo "$output" | grep -Fq "$expected" || {
    echo "smoke test failed: missing ranked size $expected" >&2
    exit 1
  }
done
echo "$output" | grep -Fq '[i]   Session artifacts:    8' || {
  echo "smoke test failed: session-artifact volume summary was missing" >&2
  exit 1
}
echo "$output" | grep -Fq '[+] [1] codex | 100 B | modified 2026-07-04' || {
  echo "smoke test failed: newest session did not rank ahead of larger older artifacts" >&2
  exit 1
}
ranked_count="$(echo "$output" | grep -Ec '^\[\+\] \[[1-3]\].*\| modified [0-9]{4}-[0-9]{2}-[0-9]{2}')"
[ "$ranked_count" -eq 7 ] || {
  echo "smoke test failed: expected ranked session files for Codex, Claude Code, Cursor, and Grok" >&2
  exit 1
}
echo "$output" | grep -Fxq "        $fixture_home/.cursor/projects/workspace/agent-transcripts/cursor-session/cursor-session.jsonl" || {
  echo "smoke test failed: ranked session path was not copy/paste-ready" >&2
  exit 1
}
echo "$output" | grep -Fq 'linked.jsonl' && {
  echo "smoke test failed: followed or ranked a session symlink" >&2
  exit 1
}
echo "$output" | grep -Fq 'excluded-fourth.jsonl' && {
  echo "smoke test failed: emitted a fourth-ranked session file" >&2
  exit 1
}

cap_home="$(mktemp -d)"
mkdir -p "$cap_home/.codex/sessions"
for i in $(seq 1 1251); do
  : > "$cap_home/.codex/unrelated-$i"
done
for i in $(seq 1 10001); do
  : > "$cap_home/.codex/sessions/$i.jsonl"
done
cap_output="$(HOME="$cap_home" "$SMOKE_BIN" ignored)"
rm -rf "$cap_home"
echo "$cap_output" | grep -q '^\[i\] PRIORITIZED SESSION ARTIFACTS (newest first) (partial scan)$' || {
  echo "smoke test failed: 10,000-entry cap did not mark ranking partial" >&2
  exit 1
}
echo "$cap_output" | grep -Fq '[i]   Session artifacts:    10000 (partial scan)' || {
  echo "smoke test failed: capped session volume was not labeled partial" >&2
  exit 1
}
echo "$cap_output" | grep -Fq '    logs: partial (0 versions observed)' || {
  echo "smoke test failed: capped Codex root scan did not mark the database family partial" >&2
  exit 1
}

echo "POSIX smoke test passed"
