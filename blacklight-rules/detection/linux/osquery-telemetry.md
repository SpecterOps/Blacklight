# Linux osquery telemetry

Use this profile to inventory local AI artifacts and record file changes or
access events on Linux.

> [!CAUTION]
> Access monitoring is opt-in and can be high volume. Validate it on one host
> before broad deployment.

## Quick path

1. Run the metadata-only inventory query.
2. Merge the supplied file-event profile into your fleet configuration.
3. Enable osquery events and run `osqueryd` with the required privilege.
4. Generate one test event and confirm the scheduled result reaches your logger.
5. Tune paths and access monitoring before fleet rollout.

## 1. Inventory the host

From the `blacklight-rules` directory:

```zsh
osqueryi < inventory/blacklight_artifact_inventory_posix.sql
```

This query reports known artifact paths, owners, modes, sizes, and modification
times. It does not read artifact contents.

Check for group- or world-readable high-value artifacts:

```zsh
osqueryi < inventory/blacklight_exposed_artifacts_posix.sql
```

## 2. Deploy the file-event profile

Merge
[osquery-file-events.conf](osquery-file-events.conf)
into the configuration managed by your fleet. Do not overwrite unrelated
scheduled queries or path categories.

The supplied profile monitors supported artifact roots under:

```text
/home/%
/root
```

It also includes the standalone `.claude.json` file.

Start `osqueryd` with:

```text
--disable_events=false
--enable_file_events=true
```

Run the daemon with enough privilege to monitor the configured paths. Send the
scheduled `blacklight_posix_file_events` results through your existing osquery
logger.

## 3. Choose change or access coverage

The `file_paths` section emits file-change events. The included
`file_accesses` entry additionally requests access events on Linux:

```json
"file_accesses": [
  "blacklight_agent_artifacts"
]
```

Keep it when access evidence is required. Remove it when the event volume is
unacceptable or your deployment only needs file changes.

## 4. Validate the result

Use a test artifact that exists on the host. Opening the file without printing
it can generate an access event when access monitoring is supported and active:

```zsh
cat "$HOME/.codex/auth.json" >/dev/null
```

For a change event, create or modify a non-sensitive test file inside a
monitored artifact root:

```zsh
touch "$HOME/.codex/blacklight-telemetry-test"
```

Wait at least 70 seconds for the profile's 60-second schedule, then inspect the
destination used by your osquery logger.

Expected query name:

```text
blacklight_posix_file_events
```

## 5. Triage and tune

Start with these fields:

| Field | Use |
| --- | --- |
| `category` | Confirm `blacklight_agent_artifacts` coverage |
| `target_path` | Identify the affected artifact |
| `action` | Identify the reported filesystem action |
| `time` | Correlate with process and network telemetry |

Never infer a file read from a modification event. Correlate suspicious access
or changes with process execution, the active user session, archive creation,
and outbound network activity.

Broad recursive roots can generate substantial traffic from caches, SQLite
databases, WAL files, and normal AI-client activity. Narrow `file_paths` to
high-value artifacts or prioritize those children in the SIEM before fleet
rollout.

See the
[osquery File Integrity Monitoring documentation](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
for Linux publisher behavior and wildcard syntax.
