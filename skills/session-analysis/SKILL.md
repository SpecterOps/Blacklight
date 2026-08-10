---
name: session-analysis
description: Safely interpret and communicate findings from AI coding-agent session data. Use when analyzing paired exported session-report JSON and text files (including Blacklight Codex reports), approved `.codex` session artifacts, session-history JSON/JSONL, tool activity, or aggregate session metrics; when comparing sessions, identifying authorized security-assessment attack-path pivots, or explaining privacy and data-handling implications.
---

# Session Analysis

Treat session data as sensitive by default. It can contain user prompts, model responses, tool inputs and outputs, workspace paths, source snippets, identifiers, secrets, personal data, and client-confidential material.

## Read report pairs

Expect a JSON and a text report in the same output directory. Read both before drawing conclusions.

- Treat JSON as the structured source for counts, session records, score distributions, response states, indicator categories, parsing coverage, and report content-policy fields.
- Treat the text report as the human-readable companion. Use it to confirm report scope, collection context, headings, and narrative explanations.
- Reconcile material differences between the two outputs. Prefer the JSON for exact metrics, identify a report-generation inconsistency when the text conflicts with it, and do not silently combine mismatched runs.
- Avoid reproducing raw paths, titles, matched values, hashes, prompts, responses, or credential-like material from either format unless explicitly necessary and permitted.

## Choose the source

Use an exported report whenever it answers the question. For example, Blacklight reports under a directory such as `.../codex/` can provide session-level metadata and indicators without opening raw session data.

Inspect an actual `.codex` root only when the user explicitly authorizes that path and raw detail is necessary. Treat it as a higher-risk source: enumerate narrowly, inspect the minimum files needed, and avoid recursively reading or copying the root by default.

Do not access another user, a shared mount, a backup, or a cloud-synced location without explicit authorization and appropriate access controls.

## Work safely

1. Confirm the purpose, source path, permitted audience, and whether the data is client, regulated, or otherwise sensitive.
2. Apply the organization’s data-classification, retention, access-control, incident, and client-contract policies. Ask for direction if the required handling is unknown.
3. Minimize collection. Start with counts, timestamps, statuses, sizes, categories, and report-provided indicators. Open raw prompts, responses, or tool payloads only when essential to the stated question.
4. Redact or summarize sensitive values. Do not reproduce secrets, access tokens, credentials, personal data, private source code, full prompts/responses, or unique client identifiers in chat, reports, tickets, or commits.
5. State the scope and limitations: report versus raw artifacts, files reviewed, time range, redactions, and any uninspected data.

## External processing and model use

Keep raw session data in the approved environment by default. Do not upload, paste, index, embed, or otherwise send it to an external model, SaaS, telemetry service, or third-party connector unless the user confirms that the organization’s policy, client terms, and approvals permit that exact transfer.

For client data, use only approved controls. A managed/private deployment such as Amazon Bedrock may be appropriate only if the organization has approved the model, AWS account and region, identity and network boundaries, logging/retention settings, and contractual/data-residency requirements. Hosting is not itself authorization. Prefer de-identified, minimized extracts even in an approved environment.

## Analyze for an authorized attack path

Use report metadata to formulate prioritized, evidence-labeled pivots for an authorized security assessment. Separate observations, hypotheses, and validation actions.

Prioritize sessions or artifacts by score, recency, activity volume, response availability, and distinct indicator categories. Explain what each category can suggest without treating it as proof:

- `credential_secret`: possible secret references; validate handling and exposure through approved procedures, not by using or disclosing a suspected value.
- `cloud_identity`: possible cloud-account or identity context; validate authorization, identity boundaries, and intended access paths.
- `internal_host` and `network_target`: possible internal services or reachable targets; validate scope, ownership, and permitted connectivity before further assessment.
- `source_control` and `agent_filesystem`: possible code, workspace, or agent-data context; use them to refine scope and identify where to seek corroborating evidence.

Recommend the least-invasive next action that can validate the hypothesis. Do not represent a category match, high score, or session content as a confirmed credential, accessible host, privilege, or exploitable path.

## Analyze and communicate

Separate observations from interpretation. Report useful patterns such as session volume, timing, request/response/tool-event counts, failures, parse errors, data-volume outliers, repeated indicator categories, and differences across tools or projects. Explain uncertainty and avoid claiming raw-content facts from metadata alone.

Use this compact structure unless the user requests another format:

- Scope and handling: source, period, authorization, and redactions
- Findings: aggregate facts and relevant outliers
- Interpretation: likely meaning and confidence
- Attack-path relevance: authorized pivot hypothesis, evidence, and constraints
- Risks: privacy, data exposure, operational, or quality concerns
- Recommended next steps: least-invasive validation action

If raw artifacts reveal a likely credential, privacy, or client-data exposure, stop broad inspection, minimize further handling, preserve only the evidence required by policy, and direct the user to their organization’s incident-response process.
