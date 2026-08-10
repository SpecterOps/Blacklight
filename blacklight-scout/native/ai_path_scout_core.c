/*
 * Blacklight Scout - shared AI path scout core
 */

#include "ai_path_scout_core.h"

static int bl_ascii_lower(int value) {
    if (value >= 'A' && value <= 'Z') {
        return value + ('a' - 'A');
    }
    return value;
}

static int bl_ascii_equal_n(const char *left, int left_len, const char *right) {
    int i = 0;
    if (!left || left_len < 0 || !right) {
        return 0;
    }
    while (i < left_len && right[i]) {
        if (bl_ascii_lower((unsigned char)left[i]) != bl_ascii_lower((unsigned char)right[i])) {
            return 0;
        }
        i++;
    }
    return i == left_len && right[i] == '\0';
}

static int bl_csv_contains_token(const char *csv, int csv_len, const char *value) {
    int start = 0;
    int end;
    if (!csv || csv_len <= 0 || !value) {
        return 1;
    }
    while (start < csv_len) {
        while (start < csv_len && (csv[start] == ',' || csv[start] == ' ' || csv[start] == '\t')) {
            start++;
        }
        end = start;
        while (end < csv_len && csv[end] != ',') {
            end++;
        }
        while (end > start && (csv[end - 1] == ' ' || csv[end - 1] == '\t')) {
            end--;
        }
        if (end > start && bl_ascii_equal_n(csv + start, end - start, value)) {
            return 1;
        }
        start = end + 1;
    }
    return 0;
}

static int bl_ascii_equals(const char *left, const char *right) {
    int len = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[len]) {
        len++;
    }
    return bl_ascii_equal_n(left, len, right);
}

int bl_loader_filter_tool(const char *value, int value_len, const char **canonical) {
    if (canonical) {
        *canonical = 0;
    }
    if (!value || value_len <= 0) {
        return 0;
    }
    if (bl_ascii_equal_n(value, value_len, "codex")) {
        if (canonical) {
            *canonical = "codex";
        }
        return 1;
    }
    if (bl_ascii_equal_n(value, value_len, "claude") ||
        bl_ascii_equal_n(value, value_len, "claude_code") ||
        bl_ascii_equal_n(value, value_len, "claude-code")) {
        if (canonical) {
            *canonical = "claude_code";
        }
        return 1;
    }
    if (bl_ascii_equal_n(value, value_len, "cursor")) {
        if (canonical) {
            *canonical = "cursor";
        }
        return 1;
    }
    if (bl_ascii_equal_n(value, value_len, "antigravity") ||
        bl_ascii_equal_n(value, value_len, "antigravity_cli") ||
        bl_ascii_equal_n(value, value_len, "antigravity-cli") ||
        bl_ascii_equal_n(value, value_len, "gemini-antigravity-cli")) {
        if (canonical) {
            *canonical = "antigravity_cli";
        }
        return 1;
    }
    return 0;
}

static int bl_tool_filter_matches(const char *csv, int csv_len, const char *tool) {
    if (!csv || csv_len <= 0 || !tool) {
        return 1;
    }
    if (bl_csv_contains_token(csv, csv_len, tool)) {
        return 1;
    }
    if (bl_ascii_equals(tool, "claude_code") &&
        (bl_csv_contains_token(csv, csv_len, "claude") ||
         bl_csv_contains_token(csv, csv_len, "claude-code"))) {
        return 1;
    }
    if (bl_ascii_equals(tool, "antigravity_cli") &&
        (bl_csv_contains_token(csv, csv_len, "antigravity") ||
         bl_csv_contains_token(csv, csv_len, "antigravity-cli") ||
         bl_csv_contains_token(csv, csv_len, "gemini-antigravity-cli"))) {
        return 1;
    }
    return 0;
}

int bl_target_allowed(const char *tool, const bl_scan_filters_t *filters) {
    if (!filters) {
        return 1;
    }
    if (!bl_tool_filter_matches(filters->tools, filters->tools_len, tool)) {
        return 0;
    }
    if (filters->exclude_tools_len > 0 &&
        bl_tool_filter_matches(filters->exclude_tools, filters->exclude_tools_len, tool)) {
        return 0;
    }
    return 1;
}

const char *bl_parser_hint_for_family(const char *family) {
    if (!family) {
        return "unknown";
    }
    if (bl_ascii_equals(family, "auth") || bl_ascii_equals(family, "credential_metadata")) {
        return "credential-session-metadata";
    }
    if (bl_ascii_equals(family, "sessions") || bl_ascii_equals(family, "history") ||
        bl_ascii_equals(family, "transcripts")) {
        return "session-detail";
    }
    if (bl_ascii_equals(family, "config") || bl_ascii_equals(family, "mcp") || bl_ascii_equals(family, "mcp_config") ||
        bl_ascii_equals(family, "project_config") || bl_ascii_equals(family, "project_mcp_config") ||
        bl_ascii_equals(family, "rules") || bl_ascii_equals(family, "sandbox") ||
        bl_ascii_equals(family, "permissions") || bl_ascii_equals(family, "plugins") ||
        bl_ascii_equals(family, "extensions") || bl_ascii_equals(family, "skills")) {
        return "config-rules";
    }
    if (bl_ascii_equals(family, "state") || bl_ascii_equals(family, "telemetry")) {
        return "sqlite-metadata";
    }
    if (bl_ascii_equals(family, "workspace")) {
        return "inventory-only";
    }
    return "unknown";
}

int bl_triage_priority_tier(const char *family, int secret_like_path) {
    if (bl_ascii_equals(family, "auth") || bl_ascii_equals(family, "credential_metadata") ||
        secret_like_path) {
        return 1;
    }
    if (bl_ascii_equals(family, "config") || bl_ascii_equals(family, "mcp") || bl_ascii_equals(family, "mcp_config") ||
        bl_ascii_equals(family, "project_config") || bl_ascii_equals(family, "project_mcp_config") ||
        bl_ascii_equals(family, "rules") || bl_ascii_equals(family, "sandbox") ||
        bl_ascii_equals(family, "permissions") || bl_ascii_equals(family, "plugins") ||
        bl_ascii_equals(family, "extensions") || bl_ascii_equals(family, "skills")) {
        return 2;
    }
    if (bl_ascii_equals(family, "sessions") || bl_ascii_equals(family, "history") ||
        bl_ascii_equals(family, "transcripts")) {
        return 3;
    }
    if (bl_ascii_equals(family, "workspace") || bl_ascii_equals(family, "state") ||
        bl_ascii_equals(family, "telemetry") || bl_ascii_equals(family, "plans") ||
        bl_ascii_equals(family, "worktrees") || bl_ascii_equals(family, "snapshots")) {
        return 4;
    }
    return 5;
}

const char *bl_triage_parser_hint(const char *family, int sqlite_path) {
    if (sqlite_path || bl_ascii_equals(family, "state") || bl_ascii_equals(family, "telemetry")) {
        return "sqlite-metadata";
    }
    return bl_parser_hint_for_family(family);
}

void bl_scan_static_targets(
    const bl_path_target_t *targets,
    size_t target_count,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    int (*expand_path)(const void *pattern, void *expanded, size_t expanded_size),
    int (*report_path_if_exists)(
        const char *tool,
        const char *family,
        const void *path,
        bl_scan_results_t *results,
        const bl_scan_filters_t *filters,
        bl_emit_fn emit
    ),
    bl_emit_fn emit
) {
    size_t i;
    unsigned char expanded[BL_MAX_PATH_LEN * sizeof(unsigned short)];

    if (!targets || !results || !expand_path || !report_path_if_exists || !emit) {
        return;
    }

    for (i = 0; i < target_count; i++) {
        if (!expand_path(targets[i].pattern, expanded, BL_MAX_PATH_LEN)) {
            continue;
        }
        report_path_if_exists(targets[i].tool, targets[i].family, expanded, results, filters, emit);
    }
}
