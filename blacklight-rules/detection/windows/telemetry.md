# Windows Security 4663 telemetry

Use this workflow to record reads of high-value local AI artifacts with Windows
Security event `4663`.

> [!IMPORTANT]
> Event `4663` is not emitted for ordinary file reads by default. Windows needs
> both the **Audit File System** policy and a matching auditing **SACL** on each
> monitored file or directory.

## Quick path

1. Open an elevated PowerShell in the repository root.
2. Audit the current policy and SACL state.
3. Apply high-value coverage if either prerequisite is missing.
4. Generate one test read and confirm event `4663`.
5. Send the events to the SIEM or roll back the local test.

The included utility operates on the current user's `%USERPROFILE%`. It does
not enumerate other user profiles.

## 1. Check the current state

Run the read-only audit:

```powershell
.\blacklight-rules\powershell\Invoke-BlacklightWindowsTelemetry.ps1
```

For a target to produce read telemetry, confirm:

| Check | Expected result |
| --- | --- |
| `FileSystemAuditPolicy` | `Success`, not `No Auditing` |
| `ReadAuditAcePresent` | `True` |

A non-elevated audit warns that results may be incomplete and reports
`CanApplyOrRollback : False`. The `Apply` and `Rollback` modes stop without
making changes when the shell is not elevated.

## 2. Enable high-value coverage

If either prerequisite is missing:

```powershell
.\blacklight-rules\powershell\Invoke-BlacklightWindowsTelemetry.ps1 -Mode Apply
```

The default `HighValue` mode:

- adds read-audit SACLs to every existing high-value target in the current
  profile, including `.codex\auth.json`
- saves rollback state under `%ProgramData%\Blacklight\`
- restricts that state to Administrators and SYSTEM
- preserves DACLs by storing and changing only SACL state
- enables the advanced-audit subcategory override when required

Use `AllRoots` only when you need recursive coverage of every supported
artifact root. It produces more events.

If `Apply` fails after saving state, the script attempts automatic rollback.
If state files remain, use the rollback command below. Domain or local Group
Policy can replace the local advanced-audit setting, so recheck after policy
refreshes.

## 3. Generate and find a test event

Open `auth.json` without printing its contents:

```powershell
[void][System.IO.File]::ReadAllBytes("$env:USERPROFILE\.codex\auth.json")
```

In Event Viewer:

1. Open **Windows Logs → Security**.
2. Filter on event ID `4663`.
3. Find the target in `Object Name`.
4. Inspect `Process Name`, `Subject`, and `Accesses`.

For a copy-and-paste PowerShell view:

```powershell
$target = "$env:USERPROFILE\.codex\auth.json"

Get-WinEvent -LogName Security -MaxEvents 1000 |
  Where-Object Id -eq 4663 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($field in $xml.Event.EventData.Data) {
      $data[$field.Name] = $field.'#text'
    }
    if ($data.ObjectName -eq $target) {
      [pscustomobject]@{
        Time = $_.TimeCreated
        User = $data.SubjectUserName
        Process = $data.ProcessName
        AccessMask = $data.AccessMask
        Accesses = $data.AccessList
      }
    }
  } | Format-Table -AutoSize
```

Expected output resembles:

![Event 4663 example](../../docs/assets/event_4663.png)

For the test read, `AccessMask` `0x1` and `Accesses` `%%4416` mean
`ReadData`.

## 4. Hunt in the SIEM

The direct-read queries use Security event `4663`, `ObjectType=File`, and
`ReadData/ListDirectory` (`%%4416`).

### Matching boundary

Every query matches an exact root or a descendant separated by `\`. It does not
intentionally match lookalike siblings such as `.codex-old`. The standalone
home file `.claude.json` is matched exactly.

Monitored roots:

- `\.codex`
- `\.claude`
- `\.cursor`
- `\.gemini\antigravity-cli`
- `\.grok`
- `\.claude.json`

Expected reads by the owning AI client, approved backup or indexing tools, and
EDR products are normal tuning candidates. Match allowlists to a known process,
target path, and user context instead of suppressing the entire artifact root.

### Splunk SPL

Data source: Windows Security 4663 forwarded to `WinEventLog:Security` or
`XmlWinEventLog:Security`. Field aliases vary by Windows TA version, so the
query coalesces common names and falls back to `_raw` for the access token.

```spl
(EventCode=4663 OR EventID=4663) (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security")
| eval object_name=lower(coalesce(ObjectName,Object_Name)), object_type=lower(coalesce(ObjectType,Object_Type)), process_name=coalesce(ProcessName,Process_Name), actor=coalesce(SubjectUserName,Account_Name,user), access_data=coalesce(AccessList,Accesses,_raw)
| where object_type="file" AND isnotnull(object_name)
    AND (
      match(object_name,"(?i)\\\\(?:[.]codex|[.]claude|[.]cursor|[.]grok)(?:\\\\|$)")
      OR match(object_name,"(?i)\\\\[.]gemini\\\\antigravity-cli(?:\\\\|$)")
      OR match(object_name,"(?i)\\\\[.]claude[.]json$")
    )
    AND (like(access_data,"%4416%") OR match(access_data,"(?i)ReadData|ListDirectory"))
| eval blacklight_tool=case(
    match(object_name,"(?i)\\\\[.]codex(?:\\\\|$)"),"codex",
    match(object_name,"(?i)\\\\[.]claude(?:\\\\|[.]json$)"),"claude_code",
    match(object_name,"(?i)\\\\[.]cursor(?:\\\\|$)"),"cursor",
    match(object_name,"(?i)\\\\[.]gemini\\\\antigravity-cli(?:\\\\|$)"),"antigravity_cli",
    match(object_name,"(?i)\\\\[.]grok(?:\\\\|$)"),"grok",
    true(),"unknown"
  )
| stats count min(_time) as first_seen max(_time) as last_seen values(process_name) as process_name values(access_data) as access_data by host actor object_name blacklight_tool
| convert ctime(first_seen) ctime(last_seen)
```

### Microsoft Sentinel KQL

Data source: `SecurityEvent` with Windows Security 4663. `EventData` is the
reliable location for `%%4416` when `AccessList` is not separately normalized.

```kusto
SecurityEvent
| where EventID == 4663 and ObjectType =~ "File"
| extend object_name = tolower(ObjectName),
         process_name = tostring(ProcessName),
         actor = tostring(coalesce(Account, AccountName)),
         event_data = tostring(EventData)
| where object_name matches regex @"\\(?:[.]codex|[.]claude|[.]cursor|[.]grok)(?:\\|$)"
    or object_name matches regex @"\\[.]gemini\\antigravity-cli(?:\\|$)"
    or object_name matches regex @"\\[.]claude[.]json$"
| where event_data contains "%%4416"
| extend blacklight_tool = case(
    object_name matches regex @"\\[.]codex(?:\\|$)", "codex",
    object_name matches regex @"\\[.]claude(?:\\|[.]json$)", "claude_code",
    object_name matches regex @"\\[.]cursor(?:\\|$)", "cursor",
    object_name matches regex @"\\[.]gemini\\antigravity-cli(?:\\|$)", "antigravity_cli",
    object_name matches regex @"\\[.]grok(?:\\|$)", "grok",
    "unknown"
  )
| project TimeGenerated, Computer, actor, process_name, object_name, AccessMask, blacklight_tool
| order by TimeGenerated desc
```

### Elastic Security KQL

Data source: Winlogbeat or Elastic Agent Windows Security events with
`winlog.event_data.*` fields.

This full-path search requires KQL leading wildcards to be enabled in Kibana's
`query:allowLeadingWildcards` advanced setting. If leading wildcards are
disabled, materialize a normalized `blacklight.artifact_root` field in the
ingest pipeline and filter on that field.

```text
event.code: "4663" and
winlog.event_data.ObjectType: "File" and
winlog.event_data.AccessList: *%%4416* and
(
  winlog.event_data.ObjectName: *\\.codex or
  winlog.event_data.ObjectName: *\\.codex\\* or
  winlog.event_data.ObjectName: *\\.claude or
  winlog.event_data.ObjectName: *\\.claude\\* or
  winlog.event_data.ObjectName: *\\.claude.json or
  winlog.event_data.ObjectName: *\\.cursor or
  winlog.event_data.ObjectName: *\\.cursor\\* or
  winlog.event_data.ObjectName: *\\.grok or
  winlog.event_data.ObjectName: *\\.grok\\* or
  winlog.event_data.ObjectName: *\\.gemini\\antigravity-cli or
  winlog.event_data.ObjectName: *\\.gemini\\antigravity-cli\\*
)
```

### Google SecOps UDM Search

Data source: parser-normalized file events mapping actual reads or opens to UDM
`FILE_READ` or `FILE_OPEN` and populating `target.file.full_path`.

```text
(metadata.event_type = "FILE_READ" OR metadata.event_type = "FILE_OPEN")
AND (
  target.file.full_path = /\\(?:[.]codex|[.]claude|[.]cursor|[.]grok)(?:\\|$)/ NOCASE
  OR target.file.full_path = /\\[.]gemini\\antigravity-cli(?:\\|$)/ NOCASE
  OR target.file.full_path = /\\[.]claude[.]json$/ NOCASE
)
```

### Microsoft Defender XDR Advanced Hunting

Data source: `DeviceProcessEvents`.

> [!WARNING]
> This is an indirect hunt for command lines that reference an in-scope path.
> It does not prove a read.

`artifact_priority` distinguishes whole-root collection from references to
especially sensitive child files.

```kusto
DeviceProcessEvents
| extend command_line = tolower(ProcessCommandLine)
| where command_line matches regex @"\\(?:[.]codex|[.]claude|[.]cursor|[.]grok)(?:\\|$|[\\\"' ])"
    or command_line matches regex @"\\[.]gemini\\antigravity-cli(?:\\|$|[\\\"' ])"
    or command_line matches regex @"\\[.]claude[.]json(?:$|[\"' ])"
| extend artifact_priority = iff(
    command_line matches regex @"(auth[.]json|[.]credentials[.]json|config[.]toml|default[.]rules|session_index[.]jsonl|history[.]jsonl|store[.]db|ai-code-tracking[.]db|mcp_config[.]json|conversation_summaries[.]db|active_sessions[.]json|session_search[.]sqlite|worktrees[.]db)",
    "high_value_child",
    "root_or_other_child"
  )
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, artifact_priority
| order by Timestamp desc
```

## 5. Roll back local testing

Restore the previous audit policy, SACLs, Security log size, and
subcategory-override registry value:

```powershell
.\blacklight-rules\powershell\Invoke-BlacklightWindowsTelemetry.ps1 -Mode Rollback
```

Successful rollback deletes the saved state. Use `-StatePath` only if you
provided a custom path during `Apply`.

## References

- [Windows Security event 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [Microsoft Sentinel SecurityEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Microsoft Defender XDR DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Elastic Winlogbeat event-data fields](https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog)
- [Google SecOps UDM search](https://cloud.google.com/chronicle/docs/investigation/udm-search)
