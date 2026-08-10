# macOS osquery telemetry

Use osquery to inventory local AI artifacts, record file changes with FSEvents,
or identify the responsible process with Endpoint Security.

## Choose the evidence you need

| Need | Use |
| --- | --- |
| File creation, modification, rename, or deletion | FSEvents profile |
| Process-attributed open, write, create, rename, or truncate | Endpoint Security profile |
| Existing artifact paths and metadata | POSIX inventory queries |

> [!IMPORTANT]
> FSEvents does not provide file-access telemetry. A modification event is not
> proof of a read.

## Quick path

1. Run the metadata-only inventory query.
2. Choose FSEvents or Endpoint Security coverage.
3. Deploy the matching profile with the required permissions.
4. Generate one test event and confirm it reaches your logger.
5. Measure volume before fleet rollout.

## 1. Inventory the host

From the `blacklight-rules` directory:

```zsh
osqueryi < inventory/blacklight_artifact_inventory_posix.sql
```

This reports known artifact paths and metadata without reading their contents.

Check for group- or world-readable high-value artifacts:

```zsh
osqueryi < inventory/blacklight_exposed_artifacts_posix.sql
```

## 2. Choose a telemetry profile

### Option A: FSEvents file changes

Merge
[osquery-file-events.conf](osquery-file-events.conf)
into your fleet-managed osquery configuration.

Start `osqueryd` with:

```text
--disable_events=false
--enable_file_events=true
```

The scheduled query is:

```text
blacklight_posix_file_events
```

It monitors supported roots under `/Users/%` and `/var/root`, including the
standalone `.claude.json` file.

The shared profile contains a `file_accesses` category for Linux. It does not
make macOS FSEvents report file reads.

### Option B: Endpoint Security process events

Use Endpoint Security when you need the executable, PID, parent PID, and event
type associated with an artifact open or change.

Follow the complete
[macOS Endpoint Security deployment guide](macos-osquery-endpointsecurity.md).
It covers:

- osquery signing and entitlement checks
- Full Disk Access for the daemon executable
- the included configuration, flags, and LaunchDaemon
- safe validation and missing-event troubleshooting
- triage fields and rollout limits

Open events require macOS 13 or newer.

## 3. Validate FSEvents

Create or modify a non-sensitive test file inside a monitored artifact root:

```zsh
touch "$HOME/.codex/blacklight-telemetry-test"
sleep 70
```

Inspect the destination used by your osquery logger for the
`blacklight_posix_file_events` query.

Start triage with:

| Field | Use |
| --- | --- |
| `category` | Confirm `blacklight_agent_artifacts` coverage |
| `target_path` | Identify the changed artifact |
| `action` | Identify the FSEvents action |
| `time` | Correlate with other host telemetry |

For Endpoint Security validation and field interpretation, use the dedicated
[deployment guide](macos-osquery-endpointsecurity.md).

## 4. Tune before rollout

Broad recursive roots can produce substantial traffic from application
bundles, caches, SQLite databases, WAL files, and normal AI-client activity.

1. Measure event volume on one representative host.
2. Narrow `file_paths` when full-root visibility is unnecessary.
3. Prioritize authentication, configuration, session, history, and conversation
   artifacts in the SIEM.

See the
[osquery File Integrity Monitoring documentation](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
for macOS publisher behavior and wildcard syntax.
