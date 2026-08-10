# macOS osquery Endpoint Security telemetry

Use this profile to record **which process accessed a monitored AI artifact**.
It adds Endpoint Security process context to osquery's FSEvents-based change
telemetry.

> [!IMPORTANT]
> An Endpoint Security `open` event proves that a process opened a file. It does
> not prove that the process read bytes from it.

## Quick path

1. Confirm that osquery has the Endpoint Security entitlement.
2. Grant Full Disk Access to the `osqueryd` executable.
3. Install the included configuration, flags, and LaunchDaemon.
4. Restart osquery and generate one test event.
5. Confirm that the result identifies both the file and the process.

This profile was validated with osquery 5.23.1 on macOS. Opening
`.codex/auth.json` with `/bin/cat` produced an `es_process_file_events` row
containing:

- `event_type=open`
- the artifact path in `filename`
- `/bin/cat` in `path`

## What the two event sources show

| Query | Source | Answers |
| --- | --- | --- |
| `blacklight_posix_file_events` | FSEvents | Was a file created, modified, renamed, or deleted? |
| `blacklight_macos_endpointsecurity_file_events` | Endpoint Security | Which process opened, wrote, created, renamed, or truncated a file? |

### Endpoint Security field guide

| Field | Meaning |
| --- | --- |
| `event_type` | The file operation, such as `open`, `write`, or `rename` |
| `filename` | The source or target artifact path |
| `dest_filename` | The destination path for operations such as rename |
| `path` | The executable responsible for the event |
| `pid` / `parent` | The responsible process and its parent |

Two fields are easy to misread:

- `event_type=open` is file-access evidence. osquery does not expose the open
  flags in this table, so the event alone cannot prove that bytes were read or
  that the file was opened read-only.
- The outer filesystem-logger field `action=added` means osquery emitted a new
  differential-query result. It is not the file operation. Use
  `columns.event_type` for Endpoint Security events and `columns.action` for
  FSEvents.

> [!NOTE]
> `es_process_file_events` only monitors paths matched by the top-level
> `file_paths` configuration. Enabling the Endpoint Security flags without
> matching paths provides no coverage. osquery does not expand `~`; use absolute
> paths and its `%`/`%%` wildcard syntax.

## 1. Check the requirements

Use the official signed macOS package. Verify the daemon executable:

```zsh
codesign --verify --strict --verbose=4 \
  /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd

codesign -d --entitlements :- \
  /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd
```

Confirm that the entitlement output contains:

```text
com.apple.developer.endpoint-security.client
```

Grant Full Disk Access to this executable:

```text
/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd
```

Granting access only to the surrounding `osquery.app` bundle is not sufficient
for a LaunchDaemon. Restart `osqueryd` after changing Full Disk Access.

The supplied flags enable:

```text
--disable_events=false
--enable_file_events=true
--disable_endpointsecurity=false
--disable_endpointsecurity_fim=false
--es_fim_enable_open_events=true
```

Open events require macOS 13 or newer. Run the daemon as root.

## 2. Install the local validation profile

> [!CAUTION]
> These files form a standalone validation profile. Back up any fleet-managed
> osquery configuration before replacing it.

Run these commands from the `blacklight-rules` directory:

```zsh
sudo cp detection/macos/osquery-local.conf /var/osquery/osquery.conf
sudo cp detection/macos/osquery-local.flags /var/osquery/osquery.flags
sudo cp detection/macos/io.osquery.agent.plist \
  /Library/LaunchDaemons/io.osquery.agent.plist

sudo chown root:wheel \
  /var/osquery/osquery.conf \
  /var/osquery/osquery.flags \
  /Library/LaunchDaemons/io.osquery.agent.plist

sudo chmod 0644 \
  /var/osquery/osquery.conf \
  /var/osquery/osquery.flags \
  /Library/LaunchDaemons/io.osquery.agent.plist
```

For a new service:

```zsh
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/io.osquery.agent.plist
```

For an already loaded service:

```zsh
sudo launchctl kickstart -k system/io.osquery.agent
```

Confirm that the service is running:

```zsh
sudo launchctl print system/io.osquery.agent
```

## 3. Generate and find a test event

Open a high-value artifact without printing its contents, then wait for the
60-second query interval:

```zsh
cat "$HOME/.codex/auth.json" >/dev/null
sleep 70
```

Find the resulting event:

```zsh
sudo grep '"name":"blacklight_macos_endpointsecurity_file_events"' \
  /var/log/osquery/osqueryd.results.log |
  grep '"event_type":"open"' |
  grep '/.codex/auth.json' |
  tail -5
```

Expected fields:

```json
{
  "event_type": "open",
  "filename": "/Users/alice/.codex/auth.json",
  "path": "/bin/cat",
  "pid": "4354"
}
```

## 4. Troubleshoot missing open events

If file changes appear but open events do not, inspect the running worker's
effective flags:

```sql
SELECT name, value
FROM osquery_flags
WHERE name IN (
  'disable_events',
  'disable_endpointsecurity',
  'disable_endpointsecurity_fim',
  'es_fim_enable_open_events'
);
```

Expected values:

| Flag | Expected |
| --- | --- |
| `disable_events` | `false` |
| `disable_endpointsecurity` | `false` |
| `disable_endpointsecurity_fim` | `false` |
| `es_fim_enable_open_events` | `true` |

Also confirm:

- Full Disk Access targets the `osqueryd` executable, not only the app bundle.
- `file_paths` includes the artifact with an absolute path.
- The daemon was restarted after permission or flag changes.
- The host runs macOS 13 or newer.

## 5. Triage suspicious access

Prioritize `event_type=open` events involving authentication, MCP
configuration, session, history, and conversation artifacts.

An open by the owning AI client can be normal. Review opens by:

- shells or scripting runtimes
- archivers or synchronization tools
- unexpected unsigned executables

Correlate the event with:

- `filename` and the Blacklight artifact catalog or inventory priority
- `path`, `pid`, and `parent` from process execution telemetry
- the actor UID and interactive session active at `time`
- later archive creation, outbound network activity, or cloud audit events

Do not suppress every event from a common shell or interpreter. Prefer an
allowlist that combines a known process identity, expected target paths, and
user context.

## Rollout guidance

Broad recursive roots produce substantial open-event volume from normal
application bundles, caches, SQLite databases, and WAL files.

Before fleet rollout:

1. Measure event volume with the local profile.
2. Narrow `file_paths` to high-value artifacts when full-root visibility is not
   required.
3. Apply SIEM-side prioritization to any remaining broad coverage.
