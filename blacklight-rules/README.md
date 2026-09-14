# Blacklight Rules

Blacklight Rules helps defenders find and monitor local AI-agent artifacts
after a host compromise.

## Start here

Choose the operating system you need:

| Operating system | Setup guide | Telemetry |
| --- | --- | --- |
| Windows | [Windows Security 4663 telemetry](detection/windows/telemetry.md) | File reads with process and user context |
| Linux | [Linux osquery telemetry](detection/linux/osquery-telemetry.md) | File changes and optional access events |
| macOS | [macOS osquery telemetry](detection/macos/osquery-telemetry.md) | FSEvents changes or Endpoint Security process events |

Each guide covers inventory, setup, validation, triage, and rollout limits.

## Repository layout

| Folder | Contents |
| --- | --- |
| `detection/` | OS-specific setup guides and profiles (`windows/`, `linux/`, and `macos/`) |
| `inventory/` | Metadata-only artifact discovery and POSIX exposure checks |
| `powershell/` | Windows audit-policy and SACL setup with rollback |
| `catalog/` | Canonical artifact paths shared with Blacklight target coverage |

## Enterprise cloud activity feeds

Endpoint telemetry shows access to local artifacts. Pair it with cloud audit
data when the provider makes that data available.

- [OpenAI Compliance Platform](https://help.openai.com/en/articles/9261474-openai-compliance-platform-for-enterprise-and-edu-customers)
  provides compliance logs and an API for ChatGPT Enterprise and Edu. Export
  continuously when you need more than its 30-day retention window.
- [Claude Compliance API Activity Feed](https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed)
  records organization authentication, chat, file, project, administrative, and
  platform activity. Store each page before checkpointing its cursor.

Send endpoint and cloud events to the SIEM with their original timestamps and
source event IDs. Correlate by account, host, and time window.
