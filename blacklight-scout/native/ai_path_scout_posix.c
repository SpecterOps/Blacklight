#define _POSIX_C_SOURCE 200809L

/*
 * Blacklight Scout - POSIX loader for AI path scout
 *
 * No-argument filesystem triage for macOS and Linux shared libraries and
 * standalone executables.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "../catalog/static_targets_generated.h"
#include "ai_path_scout_core.h"

static int g_auto_select_count = 0;

#define BL_MAX_OPERATOR_TARGETS 256
#define BL_SESSION_SCAN_LIMIT 10000
#define BL_SESSION_SCAN_MAX_DEPTH 32
#define BL_SESSION_TOOL_COUNT 4
#define BL_TOP_SESSIONS_PER_TOOL 3
#define BL_TOP_SESSION_COUNT (BL_SESSION_TOOL_COUNT * BL_TOP_SESSIONS_PER_TOOL)
#define BL_DYNAMIC_DISCOVERY_LIMIT 5000
#define BL_DYNAMIC_ROOT_LIMIT (BL_DYNAMIC_DISCOVERY_LIMIT / 4)
#define BL_DYNAMIC_DISCOVERY_MAX_DEPTH 6
#define BL_CHILD_ENTRY_SCAN_LIMIT 10000
#define BL_PLAN_PREVIEW_COUNT 5
#define BL_OUTPUT_CAPACITY (64 * 1024)
#define BL_OUTPUT_TRUNCATED_MESSAGE "\n[!] Output truncated.\n"

static char g_output[BL_OUTPUT_CAPACITY];
static size_t g_output_length = 0;

static void mark_output_truncated(void) {
    const size_t message_length = sizeof(BL_OUTPUT_TRUNCATED_MESSAGE) - 1;
    const size_t output_limit = sizeof(g_output) - 1;

    if (message_length < output_limit) {
        memcpy(g_output + output_limit - message_length, BL_OUTPUT_TRUNCATED_MESSAGE, message_length);
    }
    g_output[output_limit] = '\0';
    g_output_length = output_limit;
}

static void reset_output(void) {
    g_output[0] = '\0';
    g_output_length = 0;
}

static int output_printf(const char *format, ...) {
    va_list arguments;
    int written;

    if (g_output_length >= sizeof(g_output) - 1) {
        mark_output_truncated();
        return 0;
    }

    va_start(arguments, format);
    written = vsnprintf(g_output + g_output_length, sizeof(g_output) - g_output_length, format, arguments);
    va_end(arguments);

    if (written < 0) {
        return written;
    }
    if ((size_t)written >= sizeof(g_output) - g_output_length) {
        mark_output_truncated();
        return written;
    }
    g_output_length += (size_t)written;
    return written;
}

#define printf output_printf

typedef struct {
    int priority_tier;
    int auto_select;
    long long size_bytes;
    long long child_count;
    long long modified_time;
    const char *tool;
    const char *family;
    const char *type;
    const char *parser_hint;
    char path[BL_MAX_PATH_LEN];
} bl_operator_target_t;

static bl_operator_target_t g_operator_targets[BL_MAX_OPERATOR_TARGETS];
static int g_operator_target_count = 0;

typedef struct {
    const char *tool;
    long long size_bytes;
    long long modified_time;
    char path[BL_MAX_PATH_LEN];
} bl_session_candidate_t;

static bl_session_candidate_t g_top_sessions[BL_TOP_SESSION_COUNT];
static int g_top_session_count = 0;
static int g_session_artifact_counts[BL_SESSION_TOOL_COUNT];
static int g_session_entries_scanned = 0;
static int g_session_scan_partial = 0;
static int g_session_scan_stop = 0;
static int g_dynamic_entries_scanned = 0;
static int g_dynamic_root_entries_scanned = 0;
static int g_dynamic_scan_partial = 0;
static int g_operator_target_overflow = 0;
static int g_child_entries_scanned = 0;
static int g_child_scan_partial = 0;

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static size_t inline_strlen(const char *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i] != '\0') {
        i++;
    }
    return i;
}

static int append_text(char *dst, size_t dst_size, const char *suffix) {
    size_t idx;
    size_t i = 0;
    if (!dst || !suffix || dst_size == 0) {
        return 0;
    }
    idx = inline_strlen(dst);
    while (suffix[i] && idx + 1 < dst_size) {
        dst[idx++] = suffix[i++];
    }
    if (suffix[i]) {
        dst[0] = '\0';
        return 0;
    }
    dst[idx] = '\0';
    return 1;
}

static int posix_expand_path(const void *pattern, void *expanded, size_t expanded_size) {
    const char *text_pattern = (const char *)pattern;
    char *text_expanded = (char *)expanded;
    const char *home;
    const char *cursor;
    const char *end;
    size_t needed;

    if (!text_pattern || !text_expanded || expanded_size == 0) {
        return 0;
    }

    inline_memset(text_expanded, 0, expanded_size);
    /* Computer History alone follows the configured memory root. */
    if (strcmp(text_pattern, "$HOME/.codex/memories/extensions/skysight") == 0) {
        const char *memory_root = getenv("CODEX_HOME");
        if (memory_root && *memory_root) {
            return append_text(text_expanded, expanded_size, memory_root) &&
                append_text(text_expanded, expanded_size, "/memories/extensions/skysight");
        }
    }
    if (strncmp(text_pattern, "$HOME", 5) == 0 &&
        (text_pattern[5] == '\0' || text_pattern[5] == '/')) {
        home = getenv("HOME");
        if (!home) {
            return 0;
        }
        if (!append_text(text_expanded, expanded_size, home)) {
            return 0;
        }
        if (text_pattern[5] == '/') {
            if (!append_text(text_expanded, expanded_size, text_pattern + 5)) {
                return 0;
            }
        }
        return 1;
    }

    cursor = text_pattern;
    while (*cursor) {
        if (*cursor == '$') {
            end = cursor + 1;
            while (*end && ((*end >= 'A' && *end <= 'Z') || (*end >= '0' && *end <= '9') || *end == '_')) {
                end++;
            }
            if (end > cursor + 1) {
                char key[128];
                const char *value;
                size_t key_len = (size_t)(end - cursor - 1);
                if (key_len >= sizeof(key)) {
                    return 0;
                }
                inline_memset(key, 0, sizeof(key));
                memcpy(key, cursor + 1, key_len);
                value = getenv(key);
                if (!value) {
                    return 0;
                }
                if (!append_text(text_expanded, expanded_size, value)) {
                    return 0;
                }
                cursor = end;
                continue;
            }
        }
        needed = inline_strlen(text_expanded);
        if (needed + 1 >= expanded_size) {
            text_expanded[0] = '\0';
            return 0;
        }
        text_expanded[needed] = *cursor;
        text_expanded[needed + 1] = '\0';
        cursor++;
    }
    return 1;
}

static int ascii_lower(int value) {
    if (value >= 'A' && value <= 'Z') {
        return value + ('a' - 'A');
    }
    return value;
}

static int contains_ci_n(const char *text, const char *needle, int needle_len) {
    int i;
    int j;
    int text_len;
    if (!text || !needle || needle_len <= 0) {
        return 0;
    }
    text_len = (int)inline_strlen(text);
    if (needle_len > text_len) {
        return 0;
    }
    for (i = 0; i <= text_len - needle_len; i++) {
        for (j = 0; j < needle_len; j++) {
            if (ascii_lower((unsigned char)text[i + j]) != ascii_lower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int path_token_is_boundary(char value) {
    return value == '\0' || value == '/' || value == '\\' || value == '.' || value == '_' || value == '-';
}

static int contains_token_ci_n(const char *text, const char *needle, int needle_len) {
    int i;
    int j;
    int text_len;
    if (!text || !needle || needle_len <= 0) {
        return 0;
    }
    text_len = (int)inline_strlen(text);
    if (needle_len > text_len) {
        return 0;
    }
    for (i = 0; i <= text_len - needle_len; i++) {
        if (i > 0 && !path_token_is_boundary(text[i - 1])) {
            continue;
        }
        for (j = 0; j < needle_len; j++) {
            if (ascii_lower((unsigned char)text[i + j]) != ascii_lower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == needle_len && path_token_is_boundary(text[i + needle_len])) {
            return 1;
        }
    }
    return 0;
}

static int ends_with_ci(const char *text, const char *suffix) {
    size_t text_len;
    size_t suffix_len;
    size_t i;
    if (!text || !suffix) return 0;
    text_len = inline_strlen(text);
    suffix_len = inline_strlen(suffix);
    if (suffix_len > text_len) return 0;
    for (i = 0; i < suffix_len; i++) {
        if (ascii_lower((unsigned char)text[text_len - suffix_len + i]) != ascii_lower((unsigned char)suffix[i])) return 0;
    }
    return 1;
}

static int session_file_recognized(const char *tool, const char *path) {
    if (strcmp(tool, "codex") == 0) return contains_ci_n(path, "sessions", 8) && ends_with_ci(path, ".jsonl");
    if (strcmp(tool, "claude_code") == 0) {
        return (contains_ci_n(path, "sessions", 8) || contains_ci_n(path, "projects", 8)) && ends_with_ci(path, ".jsonl");
    }
    if (strcmp(tool, "cursor") == 0) {
        return ends_with_ci(path, "store.db") || (contains_ci_n(path, "agent-transcripts", 17) && ends_with_ci(path, ".jsonl"));
    }
    if (strcmp(tool, "antigravity_cli") == 0) {
        return ends_with_ci(path, "transcript_full.jsonl") ||
            ends_with_ci(path, "transcript.jsonl") || ends_with_ci(path, "conversation_summaries.db") ||
            (contains_ci_n(path, "conversations", 13) && ends_with_ci(path, ".db"));
    }
    return 0;
}

static int session_candidate_better(const bl_session_candidate_t *left, const bl_session_candidate_t *right) {
    int comparison;
    if (left->modified_time != right->modified_time) return left->modified_time > right->modified_time;
    if (left->size_bytes != right->size_bytes) return left->size_bytes > right->size_bytes;
    comparison = strcmp(left->tool, right->tool);
    if (comparison != 0) return comparison < 0;
    return strcmp(left->path, right->path) < 0;
}

static int session_tool_slot(const char *tool) {
    if (strcmp(tool, "codex") == 0) return 0;
    if (strcmp(tool, "claude_code") == 0) return 1;
    if (strcmp(tool, "cursor") == 0) return 2;
    if (strcmp(tool, "antigravity_cli") == 0) return 3;
    return -1;
}

static void consider_session_candidate(const char *tool, const char *path, const struct stat *info) {
    bl_session_candidate_t candidate;
    int tool_slot;
    int base;
    int insert = -1;
    int i;
    if (!tool || !path || !info || !session_file_recognized(tool, path)) return;
    tool_slot = session_tool_slot(tool);
    if (tool_slot < 0) return;
    g_session_artifact_counts[tool_slot]++;
    base = tool_slot * BL_TOP_SESSIONS_PER_TOOL;
    inline_memset(&candidate, 0, sizeof(candidate));
    candidate.tool = tool;
    candidate.size_bytes = (long long)info->st_size;
    candidate.modified_time = (long long)info->st_mtime;
    memcpy(candidate.path, path, inline_strlen(path) < BL_MAX_PATH_LEN - 1 ? inline_strlen(path) : BL_MAX_PATH_LEN - 1);
    for (i = 0; i < BL_TOP_SESSIONS_PER_TOOL; i++) {
        if (g_top_sessions[base + i].tool && strcmp(g_top_sessions[base + i].path, path) == 0) return;
        if (insert < 0 && (!g_top_sessions[base + i].tool || session_candidate_better(&candidate, &g_top_sessions[base + i]))) insert = i;
    }
    if (insert < 0) return;
    if (!g_top_sessions[base + BL_TOP_SESSIONS_PER_TOOL - 1].tool) g_top_session_count++;
    for (i = BL_TOP_SESSIONS_PER_TOOL - 1; i > insert; i--) g_top_sessions[base + i] = g_top_sessions[base + i - 1];
    g_top_sessions[base + insert] = candidate;
}

static void walk_session_files(const char *tool, const char *directory, int depth) {
    DIR *dir;
    struct dirent *entry;
    char child[BL_MAX_PATH_LEN];
    struct stat info;
    size_t directory_len;
    if (g_session_scan_stop) return;
    if (depth > BL_SESSION_SCAN_MAX_DEPTH) { g_session_scan_partial = 1; return; }
    dir = opendir(directory);
    if (!dir) { g_session_scan_partial = 1; return; }
    directory_len = inline_strlen(directory);
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (g_session_entries_scanned >= BL_SESSION_SCAN_LIMIT) { g_session_scan_partial = 1; g_session_scan_stop = 1; break; }
        g_session_entries_scanned++;
        if (directory_len + inline_strlen(entry->d_name) + 2 >= sizeof(child)) { g_session_scan_partial = 1; continue; }
        inline_memset(child, 0, sizeof(child));
        memcpy(child, directory, directory_len);
        if (directory_len && child[directory_len - 1] != '/') child[directory_len] = '/';
        if (!append_text(child, sizeof(child), entry->d_name)) { g_session_scan_partial = 1; continue; }
        if (lstat(child, &info) != 0) { g_session_scan_partial = 1; continue; }
        if (S_ISLNK(info.st_mode)) continue;
        if (S_ISDIR(info.st_mode)) walk_session_files(tool, child, depth + 1);
        else if (S_ISREG(info.st_mode)) consider_session_candidate(tool, child, &info);
        if (g_session_scan_stop) break;
        errno = 0;
    }
    if (!g_session_scan_stop && errno != 0) g_session_scan_partial = 1;
    closedir(dir);
}

static int target_can_contain_sessions(const bl_operator_target_t *target) {
    if (!target || strcmp(target->type, "directory") != 0) return 0;
    if (strcmp(target->family, "sessions") == 0 || strcmp(target->family, "history") == 0) return 1;
    return strcmp(target->family, "workspace") == 0 &&
        (strcmp(target->tool, "claude_code") == 0 || strcmp(target->tool, "cursor") == 0);
}

static int session_root_seen_before(int index, const bl_operator_target_t *target) {
    int i;
    for (i = 0; i < index; i++) {
        if (target_can_contain_sessions(&g_operator_targets[i]) &&
            strcmp(g_operator_targets[i].tool, target->tool) == 0 &&
            strcmp(g_operator_targets[i].path, target->path) == 0) return 1;
    }
    return 0;
}

static void scan_session_candidates(void) {
    int i;
    inline_memset(g_top_sessions, 0, sizeof(g_top_sessions));
    inline_memset(g_session_artifact_counts, 0, sizeof(g_session_artifact_counts));
    g_top_session_count = 0;
    g_session_entries_scanned = 0;
    g_session_scan_partial = 0;
    g_session_scan_stop = 0;
    for (i = 0; i < g_operator_target_count && !g_session_scan_stop; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (target_can_contain_sessions(target)) {
            if (!session_root_seen_before(i, target)) walk_session_files(target->tool, target->path, 0);
        }
        else if (strcmp(target->type, "file") == 0 && session_file_recognized(target->tool, target->path)) {
            struct stat info;
            if (lstat(target->path, &info) == 0 && S_ISREG(info.st_mode)) consider_session_candidate(target->tool, target->path, &info);
            else g_session_scan_partial = 1;
        }
    }
}

static long long count_directory_children(const char *path, int depth) {
    DIR *dir;
    struct dirent *entry;
    char child[BL_MAX_PATH_LEN];
    struct stat info;
    long long count = 0;
    size_t path_len;
    dir = opendir(path);
    if (!dir || depth <= 0) {
        return -1;
    }
    path_len = inline_strlen(path);
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (g_child_entries_scanned >= BL_CHILD_ENTRY_SCAN_LIMIT) {
            g_child_scan_partial = 1;
            break;
        }
        g_child_entries_scanned++;
        count++;
        if (depth <= 1) {
            continue;
        }
        inline_memset(child, 0, sizeof(child));
        if (path_len + inline_strlen(entry->d_name) + 2 >= sizeof(child)) {
            continue;
        }
        memcpy(child, path, path_len);
        if (path_len > 0 && child[path_len - 1] != '/') {
            child[path_len] = '/';
            child[path_len + 1] = '\0';
        }
        if (!append_text(child, sizeof(child), entry->d_name)) {
            continue;
        }
        if (lstat(child, &info) == 0 && !S_ISLNK(info.st_mode) && S_ISDIR(info.st_mode)) {
            long long nested = count_directory_children(child, depth - 1);
            if (nested > 0) {
                count += nested;
            }
        }
    }
    closedir(dir);
    return count;
}

static void record_operator_target(
    const char *tool,
    const char *family,
    const char *type,
    const char *path,
    int priority_tier,
    const char *parser_hint,
    long long size_bytes,
    long long child_count,
    long long modified_time,
    int auto_select
) {
    bl_operator_target_t *target;
    if (g_operator_target_count >= BL_MAX_OPERATOR_TARGETS || !path) {
        g_operator_target_overflow = 1;
        return;
    }
    target = &g_operator_targets[g_operator_target_count++];
    target->priority_tier = priority_tier;
    target->auto_select = auto_select;
    target->size_bytes = size_bytes;
    target->child_count = child_count;
    target->modified_time = modified_time;
    target->tool = tool;
    target->family = family;
    target->type = type;
    target->parser_hint = parser_hint;
    inline_memset(target->path, 0, sizeof(target->path));
    strncpy(target->path, path, sizeof(target->path) - 1);
}

static int operator_target_compare(const void *left, const void *right) {
    const bl_operator_target_t *a = (const bl_operator_target_t *)left;
    const bl_operator_target_t *b = (const bl_operator_target_t *)right;
    int cmp;
    if (a->priority_tier != b->priority_tier) {
        return a->priority_tier - b->priority_tier;
    }
    if (a->auto_select != b->auto_select) {
        return b->auto_select - a->auto_select;
    }
    cmp = strcmp(a->tool, b->tool);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(a->family, b->family);
    if (cmp != 0) {
        return cmp;
    }
    return strcmp(a->path, b->path);
}

static int target_family_is(const bl_operator_target_t *target, const char *family) {
    return target && target->family && strcmp(target->family, family) == 0;
}

static int target_tool_is(const bl_operator_target_t *target, const char *tool) {
    return target && target->tool && strcmp(target->tool, tool) == 0;
}

static int target_is_file(const bl_operator_target_t *target) {
    return target && target->type && strcmp(target->type, "file") == 0;
}

static int target_is_directory(const bl_operator_target_t *target) {
    return target && target->type && strcmp(target->type, "directory") == 0;
}

static int target_is_tier2_review(const bl_operator_target_t *target) {
    return target && target->priority_tier == 2;
}

static int target_is_session_context(const bl_operator_target_t *target) {
    return target && target->priority_tier == 3;
}

static void format_size(long long size_bytes, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return;
    }
    if (size_bytes < 1024) {
        snprintf(buffer, buffer_size, "%lld B", size_bytes);
    } else if (size_bytes < 1024LL * 1024LL) {
        snprintf(buffer, buffer_size, "%.1f KB", (double)size_bytes / 1024.0);
    } else {
        snprintf(buffer, buffer_size, "%.1f MB", (double)size_bytes / (1024.0 * 1024.0));
    }
}

static void print_escaped_path(const char *path) {
    const unsigned char *cursor = (const unsigned char *)path;
    if (!cursor) return;
    while (*cursor) {
        if (*cursor == '\n') printf("\\n");
        else if (*cursor == '\r') printf("\\r");
        else if (*cursor == '\t') printf("\\t");
        else if (*cursor < 0x20 || *cursor == 0x7f) printf("\\x%02x", *cursor);
        else printf("%c", *cursor);
        cursor++;
    }
}

static void print_collection_first(void) {
    int i;
    int printed = 0;
    char size_text[32];
    printf("[i] Collect first: credential/session metadata and auth-adjacent configs\n");
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (!target->auto_select) {
            continue;
        }
        format_size(target->size_bytes, size_text, sizeof(size_text));
        printf(
            "[i]   [%d] %s %s %s %s",
            target->priority_tier,
            target->tool,
            target->family,
            target->type,
            size_text
        );
        printf("\n[i]       ");
        print_escaped_path(target->path);
        printf("\n");
        printed++;
    }
    if (!printed) {
        printf("[i]   none\n");
    }
    printf("[i]\n");
}

static void print_tier2_group(const char *tool) {
    int i;
    int count = 0;
    int files = 0;
    int dirs = 0;
    int has_config = 0;
    int has_rules = 0;
    int has_sandbox = 0;
    int has_plugins = 0;
    int has_other = 0;
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (!target_tool_is(target, tool) || !target_is_tier2_review(target)) {
            continue;
        }
        count++;
        files += target_is_file(target);
        dirs += target_is_directory(target);
        has_config |= target_family_is(target, "config") || target_family_is(target, "mcp") ||
            target_family_is(target, "mcp_config") || target_family_is(target, "project_config") ||
            target_family_is(target, "project_mcp_config") || target_family_is(target, "permissions");
        has_rules |= target_family_is(target, "rules");
        has_sandbox |= target_family_is(target, "sandbox") || strstr(target->path, "/.sandbox-secrets/") != NULL;
        has_plugins |= target_family_is(target, "plugins") || target_family_is(target, "extensions") || target_family_is(target, "skills");
        has_other |= !(target_family_is(target, "config") || target_family_is(target, "mcp") ||
            target_family_is(target, "mcp_config") || target_family_is(target, "project_config") ||
            target_family_is(target, "project_mcp_config") || target_family_is(target, "permissions") || target_family_is(target, "rules") ||
            target_family_is(target, "sandbox") || target_family_is(target, "plugins") ||
            target_family_is(target, "extensions") || target_family_is(target, "skills") ||
            strstr(target->path, "/.sandbox-secrets/") != NULL);
    }
    if (count <= 0) {
        return;
    }
    printf("[i]   [2] %s ", tool);
    {
        int labels = 0;
        if (has_config) {
            printf("config");
            labels++;
        }
        if (has_rules) {
            printf("%srules", labels ? "/" : "");
            labels++;
        }
        if (has_plugins) {
            printf("%splugins", labels ? "/" : "");
            labels++;
        }
        if (has_sandbox) {
            printf("%ssandbox", labels ? "/" : "");
            labels++;
        }
        if (has_other || labels == 0) {
            printf("%sreview", labels ? "/" : "");
        }
    }
    if (files == count) {
        printf(" files x%d", count);
    } else if (dirs == count) {
        printf(" dirs x%d", count);
    } else {
        printf(" artifacts x%d", count);
    }
    printf("\n");
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (target_tool_is(target, tool) && target_is_tier2_review(target)) {
            printf("[i]       ");
            print_escaped_path(target->path);
            printf("\n");
        }
    }
}

static void print_review_next(void) {
    int i;
    printf("[i] Review next: config, rules, plugins, sandbox state\n");
    for (i = 0; i < g_operator_target_count; i++) {
        int seen = 0;
        int j;
        if (!target_is_tier2_review(&g_operator_targets[i])) {
            continue;
        }
        for (j = 0; j < i; j++) {
            if (target_is_tier2_review(&g_operator_targets[j]) &&
                target_tool_is(&g_operator_targets[j], g_operator_targets[i].tool)) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            print_tier2_group(g_operator_targets[i].tool);
        }
    }
    printf("[i]\n");
}

static void print_session_context(void) {
    int i;
    int j;
    int printed = 0;
    int group_count = 0;
    typedef struct {
        const char *tool;
        int count;
        long long largest;
        int printed;
    } session_group_t;
    session_group_t groups[32];
    printf("[i] Session activity (collect selectively)\n");
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        int index = -1;
        if (!target_is_session_context(target)) {
            continue;
        }
        for (j = 0; j < group_count; j++) {
            if (strcmp(groups[j].tool, target->tool) == 0) {
                index = j;
                break;
            }
        }
        if (index < 0) {
            if (group_count >= (int)(sizeof(groups) / sizeof(groups[0]))) {
                continue;
            }
            index = group_count++;
            groups[index].tool = target->tool;
            groups[index].count = 0;
            groups[index].largest = 0;
            groups[index].printed = 0;
        }
        groups[index].count++;
        if (target->size_bytes > groups[index].largest) {
            groups[index].largest = target->size_bytes;
        }
    }
    while (printed < group_count) {
        int best = -1;
        for (i = 0; i < group_count; i++) {
            if (groups[i].printed) {
                continue;
            }
            if (best < 0 ||
                groups[i].count > groups[best].count ||
                (groups[i].count == groups[best].count && groups[i].largest > groups[best].largest) ||
                (groups[i].count == groups[best].count && groups[i].largest == groups[best].largest &&
                    strcmp(groups[i].tool, groups[best].tool) < 0)) {
                best = i;
            }
        }
        if (best < 0) {
            break;
        }
        {
            int tool_slot = session_tool_slot(groups[best].tool);
            int session_artifacts = tool_slot >= 0 ? g_session_artifact_counts[tool_slot] : 0;
            printf("[i]   [3] %s history/session locations x%d | %d session artifact%s%s\n", groups[best].tool, groups[best].count,
                session_artifacts, session_artifacts == 1 ? "" : "s", g_session_scan_partial ? " (partial scan)" : "");
        }
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (!target_is_session_context(target) || strcmp(target->tool, groups[best].tool) != 0) {
                continue;
            }
            printf("[i]       ");
            print_escaped_path(target->path);
            printf("\n");
        }
        groups[best].printed = 1;
        printed++;
    }
    if (!printed) {
        printf("[i]   none\n");
    }
    printf("[i]\n");
}

static void print_plan_previews(void) {
    int i;
    int plan_count = 0;
    int plan_printed = 0;
    int selected[BL_PLAN_PREVIEW_COUNT] = {-1, -1, -1, -1, -1};
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (!target_family_is(target, "plans")) continue;
        plan_count++;
        if (target_is_directory(target)) {
            printf("[i]       ");
            print_escaped_path(target->path);
            printf("\n");
            plan_printed++;
        }
    }
    for (i = 0; i < BL_PLAN_PREVIEW_COUNT; i++) {
        int j;
        int best = -1;
        for (j = 0; j < g_operator_target_count; j++) {
            const bl_operator_target_t *candidate = &g_operator_targets[j];
            int already_selected = 0;
            int k;
            if (!target_family_is(candidate, "plans") || !target_is_file(candidate)) continue;
            for (k = 0; k < i; k++) {
                if (selected[k] == j) {
                    already_selected = 1;
                    break;
                }
            }
            if (already_selected ||
                (best >= 0 && (candidate->modified_time < g_operator_targets[best].modified_time ||
                 (candidate->modified_time == g_operator_targets[best].modified_time &&
                  strcmp(candidate->path, g_operator_targets[best].path) >= 0)))) continue;
            best = j;
        }
        if (best < 0) break;
        selected[i] = best;
        printf("[i]       ");
        print_escaped_path(g_operator_targets[best].path);
        printf("\n");
        plan_printed++;
    }
    if (plan_count > plan_printed) {
        printf("[i]       ... %d additional plan artifact%s omitted\n", plan_count - plan_printed,
            plan_count - plan_printed == 1 ? "" : "s");
    }
}

static void print_low_priority(void) {
    int tier;
    int printed = 0;
    printf("[i] Other inventory\n");
    for (tier = 4; tier <= 5; tier++) {
        int i;
        for (i = 0; i < g_operator_target_count; i++) {
            int j;
            int seen = 0;
            int count = 0;
            int dirs = 0;
            int files = 0;
            const char *family = g_operator_targets[i].family;
            if (g_operator_targets[i].priority_tier != tier) {
                continue;
            }
            for (j = 0; j < i; j++) {
                if (g_operator_targets[j].priority_tier == tier &&
                    strcmp(g_operator_targets[j].family, family) == 0) {
                    seen = 1;
                    break;
                }
            }
            if (seen) {
                continue;
            }
            for (j = 0; j < g_operator_target_count; j++) {
                const bl_operator_target_t *target = &g_operator_targets[j];
                if (target->priority_tier == tier && strcmp(target->family, family) == 0) {
                    count++;
                    dirs += target_is_directory(target);
                    files += target_is_file(target);
                }
            }
            printf("[i]   [%d] %s %s x%d\n", tier, family, dirs == count ? "dirs" : (files == count ? "files" : "artifacts"), count);
            if (strcmp(family, "plans") == 0) print_plan_previews();
            else for (j = 0; j < g_operator_target_count; j++) {
                const bl_operator_target_t *target = &g_operator_targets[j];
                if (target->priority_tier == tier && strcmp(target->family, family) == 0) {
                    printf("[i]       ");
                    print_escaped_path(target->path);
                    printf("\n");
                }
            }
            printed++;
        }
    }
    if (!printed) {
        printf("[i]   none\n");
    }
    printf("[i]\n");
}

static void print_top_session_files(void) {
    int i;
    int rank = 0;
    printf("[i] PRIORITIZED SESSION ARTIFACTS (newest first)%s\n", g_session_scan_partial ? " (partial scan)" : "");
    if (g_top_session_count == 0) printf("[i]   none\n");
    for (i = 0; i < BL_TOP_SESSION_COUNT; i++) {
        char size_text[32];
        char project[BL_MAX_PATH_LEN] = {0};
        const char *project_start;
        struct tm *utc;
        time_t modified;
        const bl_session_candidate_t *target = &g_top_sessions[i];
        if (!target->tool) continue;
        rank = (i % BL_TOP_SESSIONS_PER_TOOL) + 1;
        format_size(target->size_bytes, size_text, sizeof(size_text));
        project_start = strstr(target->path, "/projects/");
        if (project_start && (strcmp(target->tool, "claude_code") == 0 || strcmp(target->tool, "cursor") == 0)) {
            size_t length = 0, last_dash = 0;
            project_start += 10;
            while (project_start[length] && project_start[length] != '/' && length + 1 < sizeof(project)) { project[length] = project_start[length]; if (project[length] == '-') last_dash = length; length++; }
            project[length] = '\0';
            if (last_dash && project[last_dash + 1]) memmove(project, project + last_dash + 1, strlen(project + last_dash + 1) + 1);
        }
        modified = (time_t)target->modified_time;
        utc = gmtime(&modified);
        printf("[+] [%d] %s | %s", rank, target->tool, size_text);
        if (utc) printf(" | modified %04d-%02d-%02d", utc->tm_year + 1900, utc->tm_mon + 1, utc->tm_mday);
        if (project[0]) {
            printf(" | project=");
            print_escaped_path(project);
        }
        printf("\n        ");
        print_escaped_path(target->path);
        printf("\n");
    }
    printf("[i]\n");
}

static void print_operator_triage_summary(void) {
    int i, tools = 0, auth = 0, sessions = 0, session_artifacts = 0;
    printf("[i] Blacklight endpoint assessment\n[i]\n");
    if (g_operator_target_count <= 0) {
        printf("[i] ASSESSMENT SUMMARY\n[i]   Tools detected:       0\n[i]   Discovery status:     COMPLETE\n[i]\n");
        return;
    }
    printf("[i] ASSESSMENT SUMMARY\n");
    for (i = 0; i < g_operator_target_count; i++) {
        int j, seen = 0;
        if (target_family_is(&g_operator_targets[i], "auth") && target_is_file(&g_operator_targets[i])) auth++;
        if (target_is_session_context(&g_operator_targets[i])) sessions++;
        for (j = 0; j < i; j++) if (strcmp(g_operator_targets[j].tool, g_operator_targets[i].tool) == 0) { seen = 1; break; }
        if (!seen) tools++;
    }
    printf("[i]   Tools detected:       %d\n", tools);
    if (auth) printf("[+]   Credential stores:    %d file%s\n", auth, auth == 1 ? "" : "s");
    if (sessions) printf("[i]   Session locations:    %d\n", sessions);
    for (i = 0; i < BL_SESSION_TOOL_COUNT; i++) session_artifacts += g_session_artifact_counts[i];
    if (sessions || g_session_scan_partial) printf("[i]   Session artifacts:    %d%s\n", session_artifacts, g_session_scan_partial ? " (partial scan)" : "");
    printf("%s   Discovery status:     %s\n[i]\n", (g_dynamic_scan_partial || g_operator_target_overflow || g_session_scan_partial) ? "[!]" : "[i]", (g_dynamic_scan_partial || g_operator_target_overflow || g_session_scan_partial) ? "PARTIAL" : "COMPLETE");
    qsort(
        g_operator_targets,
        (size_t)g_operator_target_count,
        sizeof(g_operator_targets[0]),
        operator_target_compare
    );
    print_collection_first();
    print_review_next();
    print_top_session_files();
    print_session_context();
    print_low_priority();
    if (g_operator_target_overflow) printf("[!] Result storage cap reached at %d artifacts. Results are incomplete.\n", BL_MAX_OPERATOR_TARGETS);
    if (g_dynamic_scan_partial) printf("[!] Discovery cap reached after %d candidate entries (per-root cap %d; run cap %d). Results are incomplete.\n", g_dynamic_entries_scanned, BL_DYNAMIC_ROOT_LIMIT, BL_DYNAMIC_DISCOVERY_LIMIT);
}

static void posix_emit_triage(const char *tool, const char *family, const char *type, const void *path) {
    const char *text_path = (const char *)path;
    struct stat info;
    long long size_bytes = 0;
    long long child_count = 0;
    long long modified_time = 0;
    int priority_tier;
    const char *parser_hint;
    int sandbox_secret_path;
    int auth_adjacent_config_path;
    if (stat(text_path, &info) == 0) {
        modified_time = (long long)info.st_mtime;
        if (S_ISDIR(info.st_mode)) {
            child_count = count_directory_children(text_path, 1);
            if (child_count < 0) {
                child_count = 0;
            }
        } else {
            size_bytes = (long long)info.st_size;
        }
    }
    sandbox_secret_path = contains_ci_n(text_path, ".sandbox-secrets", 16);
    auth_adjacent_config_path =
        contains_ci_n(text_path, ".claude.json", 12) &&
        !contains_ci_n(text_path, ".claude/.claude.json", 20);
    priority_tier = bl_triage_priority_tier(
        family,
        (!sandbox_secret_path &&
         !contains_ci_n(text_path, "mcp-needs-auth-cache", 21) && (
            contains_token_ci_n(text_path, "auth", 4) ||
            contains_token_ci_n(text_path, "credential", 10) ||
            contains_token_ci_n(text_path, "token", 5) ||
            contains_token_ci_n(text_path, "secret", 6)
        )) ||
        auth_adjacent_config_path
    );
    if (sandbox_secret_path && priority_tier == 1) {
        priority_tier = 2;
    }
    parser_hint = bl_triage_parser_hint(family, contains_ci_n(text_path, ".db", 3) || contains_ci_n(text_path, ".sqlite", 7));
    record_operator_target(
        tool,
        family,
        type,
        text_path,
        priority_tier,
        parser_hint,
        size_bytes,
        child_count,
        modified_time,
        priority_tier == 1 && type && type[0] == 'f'
    );
    if (priority_tier == 1 && type && type[0] == 'f') {
        g_auto_select_count++;
    }
}

static int posix_report_path_if_exists(
    const char *tool,
    const char *family,
    const void *path,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    bl_emit_fn emit
) {
    const char *text_path = (const char *)path;
    struct stat info;
    const char *type;

    if (!tool || !family || !text_path || !results || !emit) {
        return 0;
    }

    if (!bl_target_allowed(tool, filters)) {
        results->filtered_count++;
        return 0;
    }

    if (lstat(text_path, &info) != 0 || S_ISLNK(info.st_mode)) {
        return 0;
    }

    if (S_ISDIR(info.st_mode)) {
        type = "directory";
        results->directory_count++;
    } else {
        type = "file";
        results->file_count++;
    }

    results->hit_count++;
    emit(tool, family, type, text_path);
    return 1;
}

static int operator_path_recorded(const char *path) {
    int i;
    for (i = 0; i < g_operator_target_count; i++) {
        if (strcmp(g_operator_targets[i].path, path) == 0) return 1;
    }
    return 0;
}

static void report_dynamic_file(
    const char *tool,
    const char *family,
    const char *path,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    bl_emit_fn emit
) {
    if (!operator_path_recorded(path)) posix_report_path_if_exists(tool, family, path, results, filters, emit);
}

static void scan_dynamic_tree(
    const char *tool,
    const char *directory,
    int depth,
    int include_plan_metadata,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    bl_emit_fn emit
) {
    DIR *dir;
    struct dirent *entry;
    char child[BL_MAX_PATH_LEN];
    struct stat info;
    size_t directory_len;
    if (depth < 0 || g_dynamic_entries_scanned >= BL_DYNAMIC_DISCOVERY_LIMIT ||
        g_dynamic_root_entries_scanned >= BL_DYNAMIC_ROOT_LIMIT) {
        if (g_dynamic_entries_scanned >= BL_DYNAMIC_DISCOVERY_LIMIT ||
            g_dynamic_root_entries_scanned >= BL_DYNAMIC_ROOT_LIMIT) g_dynamic_scan_partial = 1;
        return;
    }
    dir = opendir(directory);
    if (!dir) return;
    directory_len = inline_strlen(directory);
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (g_dynamic_entries_scanned >= BL_DYNAMIC_DISCOVERY_LIMIT ||
            g_dynamic_root_entries_scanned >= BL_DYNAMIC_ROOT_LIMIT) { g_dynamic_scan_partial = 1; break; }
        g_dynamic_entries_scanned++;
        g_dynamic_root_entries_scanned++;
        if (directory_len + inline_strlen(entry->d_name) + 2 >= sizeof(child)) continue;
        inline_memset(child, 0, sizeof(child));
        memcpy(child, directory, directory_len);
        if (directory_len && child[directory_len - 1] != '/') child[directory_len] = '/';
        if (!append_text(child, sizeof(child), entry->d_name) || lstat(child, &info) != 0 || S_ISLNK(info.st_mode)) continue;
        if (S_ISDIR(info.st_mode)) {
            if (depth > 0) scan_dynamic_tree(tool, child, depth - 1, include_plan_metadata, results, filters, emit);
        } else if (S_ISREG(info.st_mode) && strcmp(entry->d_name, ".mcp.json") == 0) {
            report_dynamic_file(tool, "mcp", child, results, filters, emit);
        } else if (S_ISREG(info.st_mode) && strcmp(tool, "claude_code") == 0 && strcmp(entry->d_name, "sessions-index.json") == 0) {
            report_dynamic_file(tool, "sessions", child, results, filters, emit);
        } else if (S_ISREG(info.st_mode) && include_plan_metadata && ends_with_ci(entry->d_name, ".plan.md")) {
            report_dynamic_file(tool, "plans", child, results, filters, emit);
        }
    }
    closedir(dir);
}

static void scan_dynamic_targets(
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    bl_emit_fn emit
) {
    const char *home = getenv("HOME");
    char root[BL_MAX_PATH_LEN];
    char child[BL_MAX_PATH_LEN];
    DIR *dir;
    struct dirent *entry;
    struct stat info;
    if (!home || !*home) return;
    inline_memset(root, 0, sizeof(root));
    if (append_text(root, sizeof(root), home) && append_text(root, sizeof(root), "/.codex/rules")) {
        g_dynamic_root_entries_scanned = 0;
        dir = opendir(root);
        if (dir) {
            while ((entry = readdir(dir)) != NULL) {
                if (g_dynamic_entries_scanned >= BL_DYNAMIC_DISCOVERY_LIMIT ||
                    g_dynamic_root_entries_scanned >= BL_DYNAMIC_ROOT_LIMIT) { g_dynamic_scan_partial = 1; break; }
                g_dynamic_entries_scanned++;
                g_dynamic_root_entries_scanned++;
                if (!ends_with_ci(entry->d_name, ".rules")) continue;
                if (strcmp(entry->d_name, "default.rules") == 0) continue;
                inline_memset(child, 0, sizeof(child));
                if (!append_text(child, sizeof(child), root) || !append_text(child, sizeof(child), "/") ||
                    !append_text(child, sizeof(child), entry->d_name) || lstat(child, &info) != 0 || !S_ISREG(info.st_mode)) continue;
                report_dynamic_file("codex", "rules", child, results, filters, emit);
            }
            closedir(dir);
        }
    }
    inline_memset(root, 0, sizeof(root));
    g_dynamic_root_entries_scanned = 0;
    if (append_text(root, sizeof(root), home) && append_text(root, sizeof(root), "/.claude/projects"))
        scan_dynamic_tree("claude_code", root, BL_DYNAMIC_DISCOVERY_MAX_DEPTH, 0, results, filters, emit);
    inline_memset(root, 0, sizeof(root));
    g_dynamic_root_entries_scanned = 0;
    if (append_text(root, sizeof(root), home) && append_text(root, sizeof(root), "/.cursor/projects"))
        scan_dynamic_tree("cursor", root, BL_DYNAMIC_DISCOVERY_MAX_DEPTH, 0, results, filters, emit);
    inline_memset(root, 0, sizeof(root));
    g_dynamic_root_entries_scanned = 0;
    if (append_text(root, sizeof(root), home) && append_text(root, sizeof(root), "/.cursor/plans"))
        scan_dynamic_tree("cursor", root, 0, 1, results, filters, emit);
}

static void run_posix_triage(void) {
    bl_scan_results_t results;
    bl_scan_filters_t filters;
    reset_output();
    inline_memset(&results, 0, sizeof(results));
    inline_memset(&filters, 0, sizeof(filters));
    filters.max_depth = 1;
    filters.triage = 1;

    g_auto_select_count = 0;
    g_operator_target_count = 0;
    g_operator_target_overflow = 0;
    g_dynamic_entries_scanned = 0;
    g_dynamic_scan_partial = 0;
    g_child_entries_scanned = 0;
    g_child_scan_partial = 0;

    bl_scan_static_targets(
        BL_STATIC_TARGETS,
        BL_STATIC_TARGETS_COUNT,
        &results,
        &filters,
        posix_expand_path,
        posix_report_path_if_exists,
        posix_emit_triage
    );
    scan_dynamic_targets(&results, &filters, posix_emit_triage);
    scan_session_candidates();
    print_operator_triage_summary();
}

__attribute__((visibility("default"))) char *bl_scout_run(int argc, char **argv) {
    char *result;
    (void)argc;
    (void)argv;
    run_posix_triage();
    result = strdup(g_output);
    return result;
}

int main(int argc, char **argv) {
    char *output = bl_scout_run(argc, argv);
    if (output) {
        fputs(output, stdout);
        free(output);
    }
    return 0;
}
