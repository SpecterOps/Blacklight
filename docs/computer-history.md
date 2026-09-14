# Computer History memories

On macOS, Scout reports the Computer History memory directory under the existing
Codex classification and the `memories` family. It checks directory metadata;
it does not read Markdown bodies, inventory individual memories recursively,
or count them as sessions. Offline Markdown analysis is not supported.

## Storage and availability

The documented location is `$CODEX_HOME/memories/extensions/skysight/`, usually
`~/.codex/memories/extensions/skysight/`. Scout uses a nonempty `CODEX_HOME` from
its process environment, otherwise `$HOME/.codex`. Other artifact targets retain
their existing root behavior. A launcher must supply the override when the
application uses a custom root; directory presence does not prove the feature
is currently enabled.

Generated memories are readable, modifiable Markdown, may contain sensitive
information, and are not encrypted by Computer History. Other programs running
as the same macOS user may be able to access them. They remain until deleted or
cleared. Temporary interaction events are separate: they reside in the ChatGPT
App Group, require explicit permission for other apps to access, and are deleted
after 48 hours. Scout does not collect those events.

## Enable Computer History

Computer History is off by default. Business and Enterprise administrators must
grant access before members can opt in; that grant does not enable collection.

1. Open ChatGPT on macOS and select **Settings > Integrations > Computer history**.
2. Select **Turn on** and review the privacy, permissions, and storage information.
3. Enable **Memories** if prompted.
4. Choose contributing apps and websites and follow the macOS permission prompts.

Screen Recording permission is unnecessary. If the setting is missing, check
plan availability and workspace access. These are manual setup instructions;
Blacklight does not enable the feature.

## Defender review

Investigate unexpected processes reading, copying, or writing files beneath the
memory directory. Correlate the process, user, path, and subsequent activity;
file presence alone does not establish collection, compromise, or execution of
instructions from a memory. Treat generated summaries as context requiring
corroboration, not an authoritative activity log.

Use the [macOS telemetry guide](../blacklight-rules/detection/macos/osquery-telemetry.md)
and validate the selected sensor's read/write coverage. For custom storage,
configure the resolved absolute directory in inventory and telemetry rules;
default `.codex` rules do not cover arbitrary roots, and telemetry configuration
does not automatically expand another process's environment variables.

Sources: [Computer History documentation](https://learn.chatgpt.com/docs/customization/computer-history)
and [EAA-005: Transcript and agent-state collection](https://github.com/0x4D31/endpoint-ai-agent-abuse/blob/main/techniques/index.md#eaa-005--transcript-and-agent-state-collection).
