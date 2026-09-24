/*
 * Blacklight Scout - Windows BOF wrapper for AI path scout
 *
 * Snapshot BOF for Windows AI tooling artifacts. Reports bounded filesystem
 * metadata without reading file contents.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define BLACKLIGHT_SCOUT_WINDOWS 1

#include <stddef.h>
#include <stdint.h>

#include "../catalog/static_targets_generated.h"
#include "ai_path_scout_core.h"
#include "beacon.h"

#define MAX_BOF_TRIAGE_TARGETS 256
#define BOF_SESSION_SCAN_LIMIT 10000
#define BOF_SESSION_SCAN_MAX_DEPTH 32
#define BOF_SESSION_TOOL_COUNT 5
#define BOF_TOP_SESSIONS_PER_TOOL 3
#define BOF_TOP_SESSION_COUNT (BOF_SESSION_TOOL_COUNT * BOF_TOP_SESSIONS_PER_TOOL)
#define BOF_DYNAMIC_DISCOVERY_LIMIT 5000
#define BOF_DYNAMIC_ROOT_LIMIT (BOF_DYNAMIC_DISCOVERY_LIMIT / 4)
#define BOF_DYNAMIC_DISCOVERY_MAX_DEPTH 6
#define BOF_CHILD_ENTRY_SCAN_LIMIT 10000
#define BOF_CODEX_SQLITE_FAMILY_COUNT 5

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, wchar_t *, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *, SYSTEMTIME *);

static int g_auto_select_count = 0;

typedef struct {
    int priority_tier;
    int auto_select;
    long long size_bytes;
    long long child_count;
    const char *tool;
    const char *family;
    const char *type;
    const char *parser_hint;
    wchar_t path[BL_MAX_PATH_LEN];
} bof_triage_target_t;

static bof_triage_target_t g_bof_triage_targets[MAX_BOF_TRIAGE_TARGETS];
static int g_bof_triage_target_count = 0;
static int g_bof_triage_target_overflow = 0;

typedef struct {
    const char *tool;
    long long size_bytes;
    FILETIME last_write_time;
    wchar_t path[BL_MAX_PATH_LEN];
} bof_session_candidate_t;

static bof_session_candidate_t g_top_sessions[BOF_TOP_SESSION_COUNT];
static int g_top_session_count = 0;
static int g_session_artifact_counts[BOF_SESSION_TOOL_COUNT];
static int g_session_entries_scanned = 0;
static int g_session_scan_partial = 0;
static int g_session_scan_stop = 0;
static int g_dynamic_entries_scanned = 0;
static int g_dynamic_root_entries_scanned = 0;
static int g_dynamic_scan_partial = 0;
static int g_child_entries_scanned = 0;
static int g_child_scan_partial = 0;

typedef struct {
    int count;
    int has_newest;
    wchar_t newest_suffix[BL_MAX_PATH_LEN];
    wchar_t newest_path[BL_MAX_PATH_LEN];
    long long newest_size;
    FILETIME newest_write_time;
} bof_codex_sqlite_family_t;

static const char *g_codex_sqlite_family_names[BOF_CODEX_SQLITE_FAMILY_COUNT] = {
    "logs", "thread_history", "state", "memories", "goals"
};
static bof_codex_sqlite_family_t g_codex_sqlite_families[BOF_CODEX_SQLITE_FAMILY_COUNT];
static int g_codex_sqlite_check_requested = 0;
static int g_codex_sqlite_root_available = 0;
static int g_codex_sqlite_root_missing = 0;
static int g_codex_sqlite_scan_partial = 0;

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static size_t inline_wcslen(const wchar_t *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i] != L'\0') {
        i++;
    }
    return i;
}

static int build_path(const wchar_t *left, const wchar_t *right, wchar_t *out, size_t out_size) {
    size_t idx = 0;
    size_t left_idx = 0;
    size_t right_idx = 0;
    if (!left || !right || !out || out_size == 0) {
        return 0;
    }
    while (left[left_idx] && idx + 1 < out_size) {
        out[idx++] = left[left_idx++];
    }
    while (right[right_idx] && idx + 1 < out_size) {
        out[idx++] = right[right_idx++];
    }
    if (left[left_idx] || right[right_idx]) {
        out[0] = L'\0';
        return 0;
    }
    out[idx] = L'\0';
    return 1;
}

static int append_wide_in_place(wchar_t *dst, const wchar_t *suffix, size_t out_size) {
    size_t idx;
    size_t i = 0;
    if (!dst || !suffix || out_size == 0) {
        return 0;
    }
    idx = inline_wcslen(dst);
    while (suffix[i] && idx + 1 < out_size) {
        dst[idx++] = suffix[i++];
    }
    if (suffix[i]) {
        dst[0] = L'\0';
        return 0;
    }
    dst[idx] = L'\0';
    return 1;
}

static int is_dot_directory(const wchar_t *name) {
    if (!name || name[0] != L'.') {
        return 0;
    }
    if (name[1] == L'\0') {
        return 1;
    }
    return name[1] == L'.' && name[2] == L'\0';
}

static int ascii_lower(int value) {
    if (value >= 'A' && value <= 'Z') {
        return value + ('a' - 'A');
    }
    return value;
}

static wchar_t wide_lower(wchar_t value) {
    if (value >= L'A' && value <= L'Z') {
        return value + (L'a' - L'A');
    }
    return value;
}

static int wide_contains_ascii_n_ci(const wchar_t *text, const char *needle, int needle_len) {
    int i;
    int j;
    int text_len;
    if (!text || !needle || needle_len <= 0) {
        return 0;
    }
    text_len = (int)inline_wcslen(text);
    if (needle_len > text_len) {
        return 0;
    }
    for (i = 0; i <= text_len - needle_len; i++) {
        for (j = 0; j < needle_len; j++) {
            if ((wchar_t)ascii_lower((unsigned char)needle[j]) != wide_lower(text[i + j])) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int ascii_equal_n_ci(const char *left, int left_len, const char *right) {
    int i = 0;
    if (!left || left_len <= 0 || !right) {
        return 0;
    }
    while (i < left_len && right[i]) {
        if (ascii_lower((unsigned char)left[i]) != ascii_lower((unsigned char)right[i])) {
            return 0;
        }
        i++;
    }
    return i == left_len && right[i] == '\0';
}

static int c_string_len(const char *value) {
    int len = 0;
    if (!value) {
        return 0;
    }
    while (value[len]) {
        len++;
    }
    return len;
}

static long long count_immediate_children(const wchar_t *path) {
    wchar_t search[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW find_data;
    HANDLE find_handle = INVALID_HANDLE_VALUE;
    long long count = 0;

    if (!path) return -1;

    inline_memset(search, 0, sizeof(search));
    if (!build_path(path, L"\\*", search, BL_MAX_PATH_LEN)) {
        return -1;
    }

    inline_memset(&find_data, 0, sizeof(find_data));
    find_handle = KERNEL32$FindFirstFileW(search, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        if (is_dot_directory(find_data.cFileName)) {
            continue;
        }
        if (g_child_entries_scanned >= BOF_CHILD_ENTRY_SCAN_LIMIT) {
            g_child_scan_partial = 1;
            break;
        }
        g_child_entries_scanned++;
        count++;
    } while (KERNEL32$FindNextFileW(find_handle, &find_data));

    KERNEL32$FindClose(find_handle);
    return count;
}

static void copy_wide_path(wchar_t *dst, const wchar_t *src, size_t dst_count) {
    size_t i = 0;
    if (!dst || dst_count == 0) {
        return;
    }
    if (!src) {
        dst[0] = L'\0';
        return;
    }
    while (src[i] && i + 1 < dst_count) {
        dst[i] = src[i] == L'/' ? L'\\' : src[i];
        i++;
    }
    dst[i] = L'\0';
}

static int target_tool_is(const bof_triage_target_t *target, const char *tool) {
    int len = 0;
    if (!target || !target->tool || !tool) {
        return 0;
    }
    while (target->tool[len]) {
        len++;
    }
    return ascii_equal_n_ci(target->tool, len, tool);
}

static int target_family_is(const bof_triage_target_t *target, const char *family) {
    int len = 0;
    if (!target || !target->family || !family) {
        return 0;
    }
    while (target->family[len]) {
        len++;
    }
    return ascii_equal_n_ci(target->family, len, family);
}

static int target_is_file(const bof_triage_target_t *target) {
    return target && target->type && target->type[0] == 'f';
}

static int target_is_directory(const bof_triage_target_t *target) {
    return target && target->type && target->type[0] == 'd';
}

static int target_is_tier2_review(const bof_triage_target_t *target) {
    return target && target->priority_tier == 2;
}

static int target_is_session_context(const bof_triage_target_t *target) {
    return target && target->priority_tier == 3;
}

static int wide_ends_with_ascii_ci(const wchar_t *text, const char *suffix) {
    size_t text_len;
    size_t suffix_len = 0;
    size_t i;
    if (!text || !suffix) return 0;
    text_len = inline_wcslen(text);
    while (suffix[suffix_len]) suffix_len++;
    if (suffix_len > text_len) return 0;
    for (i = 0; i < suffix_len; i++) {
        if (wide_lower(text[text_len - suffix_len + i]) != (wchar_t)ascii_lower((unsigned char)suffix[i])) return 0;
    }
    return 1;
}

static int session_file_recognized(const char *tool, const wchar_t *path) {
    if (ascii_equal_n_ci(tool, c_string_len(tool), "codex")) {
        return wide_contains_ascii_n_ci(path, "sessions", 8) && wide_ends_with_ascii_ci(path, ".jsonl");
    }
    if (ascii_equal_n_ci(tool, c_string_len(tool), "claude_code")) {
        return (wide_contains_ascii_n_ci(path, "sessions", 8) || wide_contains_ascii_n_ci(path, "projects", 8)) &&
            wide_ends_with_ascii_ci(path, ".jsonl");
    }
    if (ascii_equal_n_ci(tool, c_string_len(tool), "cursor")) {
        return wide_ends_with_ascii_ci(path, "store.db") ||
            (wide_contains_ascii_n_ci(path, "agent-transcripts", 17) && wide_ends_with_ascii_ci(path, ".jsonl"));
    }
    if (ascii_equal_n_ci(tool, c_string_len(tool), "antigravity_cli")) {
        return wide_ends_with_ascii_ci(path, "transcript_full.jsonl") ||
            wide_ends_with_ascii_ci(path, "transcript.jsonl") || wide_ends_with_ascii_ci(path, "conversation_summaries.db") ||
            (wide_contains_ascii_n_ci(path, "conversations", 13) && wide_ends_with_ascii_ci(path, ".db"));
    }
    if (ascii_equal_n_ci(tool, c_string_len(tool), "grok")) {
        return wide_ends_with_ascii_ci(path, "updates.jsonl");
    }
    return 0;
}

static int wide_path_compare_ci(const wchar_t *left, const wchar_t *right) {
    size_t i = 0;
    while (left[i] && right[i]) {
        int difference = (int)wide_lower(left[i]) - (int)wide_lower(right[i]);
        if (difference) return difference;
        i++;
    }
    return (int)left[i] - (int)right[i];
}

static int session_candidate_better(const bof_session_candidate_t *left, const bof_session_candidate_t *right) {
    int comparison;
    if (left->last_write_time.dwHighDateTime != right->last_write_time.dwHighDateTime)
        return left->last_write_time.dwHighDateTime > right->last_write_time.dwHighDateTime;
    if (left->last_write_time.dwLowDateTime != right->last_write_time.dwLowDateTime)
        return left->last_write_time.dwLowDateTime > right->last_write_time.dwLowDateTime;
    if (left->size_bytes != right->size_bytes) return left->size_bytes > right->size_bytes;
    comparison = ascii_lower((unsigned char)left->tool[0]) - ascii_lower((unsigned char)right->tool[0]);
    if (comparison == 0) {
        int i = 0;
        while (left->tool[i] && right->tool[i]) {
            comparison = ascii_lower((unsigned char)left->tool[i]) - ascii_lower((unsigned char)right->tool[i]);
            if (comparison) break;
            i++;
        }
        if (!comparison) comparison = (unsigned char)left->tool[i] - (unsigned char)right->tool[i];
    }
    if (comparison != 0) return comparison < 0;
    return wide_path_compare_ci(left->path, right->path) < 0;
}

static int session_tool_slot(const char *tool) {
    int length = c_string_len(tool);
    if (ascii_equal_n_ci(tool, length, "codex")) return 0;
    if (ascii_equal_n_ci(tool, length, "claude_code")) return 1;
    if (ascii_equal_n_ci(tool, length, "cursor")) return 2;
    if (ascii_equal_n_ci(tool, length, "antigravity_cli")) return 3;
    if (ascii_equal_n_ci(tool, length, "grok")) return 4;
    return -1;
}

static void consider_session_candidate(const char *tool, const wchar_t *path, const WIN32_FIND_DATAW *data) {
    bof_session_candidate_t candidate;
    int tool_slot;
    int base;
    int insert = -1;
    int i;
    if (!tool || !path || !data || !session_file_recognized(tool, path)) return;
    tool_slot = session_tool_slot(tool);
    if (tool_slot < 0) return;
    g_session_artifact_counts[tool_slot]++;
    base = tool_slot * BOF_TOP_SESSIONS_PER_TOOL;
    inline_memset(&candidate, 0, sizeof(candidate));
    candidate.tool = tool;
    candidate.size_bytes = ((long long)data->nFileSizeHigh << 32) | data->nFileSizeLow;
    candidate.last_write_time = data->ftLastWriteTime;
    copy_wide_path(candidate.path, path, BL_MAX_PATH_LEN);
    for (i = 0; i < BOF_TOP_SESSIONS_PER_TOOL; i++) {
        if (g_top_sessions[base + i].tool && wide_path_compare_ci(g_top_sessions[base + i].path, path) == 0) return;
        if (insert < 0 && (!g_top_sessions[base + i].tool || session_candidate_better(&candidate, &g_top_sessions[base + i]))) insert = i;
    }
    if (insert < 0) return;
    if (!g_top_sessions[base + BOF_TOP_SESSIONS_PER_TOOL - 1].tool) g_top_session_count++;
    for (i = BOF_TOP_SESSIONS_PER_TOOL - 1; i > insert; i--) g_top_sessions[base + i] = g_top_sessions[base + i - 1];
    g_top_sessions[base + insert] = candidate;
}

static void walk_session_files(const char *tool, const wchar_t *directory, int depth) {
    wchar_t search[BL_MAX_PATH_LEN];
    wchar_t child[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW find_data;
    HANDLE find_handle;
    if (g_session_scan_stop) return;
    if (depth > BOF_SESSION_SCAN_MAX_DEPTH) { g_session_scan_partial = 1; return; }
    inline_memset(search, 0, sizeof(search));
    if (!build_path(directory, L"\\*", search, BL_MAX_PATH_LEN)) { g_session_scan_partial = 1; return; }
    inline_memset(&find_data, 0, sizeof(find_data));
    find_handle = KERNEL32$FindFirstFileW(search, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        if (KERNEL32$GetLastError() != ERROR_FILE_NOT_FOUND) g_session_scan_partial = 1;
        return;
    }
    do {
        if (is_dot_directory(find_data.cFileName)) continue;
        if (g_session_entries_scanned >= BOF_SESSION_SCAN_LIMIT) {
            g_session_scan_partial = 1;
            g_session_scan_stop = 1;
            break;
        }
        g_session_entries_scanned++;
        inline_memset(child, 0, sizeof(child));
        if (!build_path(directory, L"\\", child, BL_MAX_PATH_LEN) ||
            !append_wide_in_place(child, find_data.cFileName, BL_MAX_PATH_LEN)) {
            g_session_scan_partial = 1;
            continue;
        }
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) walk_session_files(tool, child, depth + 1);
        else consider_session_candidate(tool, child, &find_data);
    } while (!g_session_scan_stop && KERNEL32$FindNextFileW(find_handle, &find_data));
    if (!g_session_scan_stop && KERNEL32$GetLastError() != ERROR_NO_MORE_FILES) g_session_scan_partial = 1;
    KERNEL32$FindClose(find_handle);
}

static int target_can_contain_sessions(const bof_triage_target_t *target) {
    if (!target_is_directory(target)) return 0;
    if (target_family_is(target, "sessions") || target_family_is(target, "history")) return 1;
    return target_family_is(target, "workspace") && (target_tool_is(target, "claude_code") || target_tool_is(target, "cursor"));
}

static void scan_session_candidates(void) {
    int i;
    inline_memset(g_top_sessions, 0, sizeof(g_top_sessions));
    inline_memset(g_session_artifact_counts, 0, sizeof(g_session_artifact_counts));
    g_top_session_count = 0;
    g_session_entries_scanned = 0;
    g_session_scan_partial = 0;
    g_session_scan_stop = 0;
    for (i = 0; i < g_bof_triage_target_count && !g_session_scan_stop; i++) {
        const bof_triage_target_t *target = &g_bof_triage_targets[i];
        if (target_can_contain_sessions(target)) {
            int j;
            int seen = 0;
            for (j = 0; j < i; j++) {
                if (target_can_contain_sessions(&g_bof_triage_targets[j]) &&
                    target_tool_is(&g_bof_triage_targets[j], target->tool) &&
                    wide_path_compare_ci(g_bof_triage_targets[j].path, target->path) == 0) { seen = 1; break; }
            }
            if (!seen) walk_session_files(target->tool, target->path, 0);
        }
        else if (target_is_file(target) && session_file_recognized(target->tool, target->path)) {
            WIN32_FIND_DATAW find_data;
            HANDLE find_handle;
            inline_memset(&find_data, 0, sizeof(find_data));
            find_handle = KERNEL32$FindFirstFileW(target->path, &find_data);
            if (find_handle != INVALID_HANDLE_VALUE) {
                if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) consider_session_candidate(target->tool, target->path, &find_data);
                KERNEL32$FindClose(find_handle);
            } else {
                g_session_scan_partial = 1;
            }
        }
    }
}

static void record_bof_triage_target(
    const char *tool,
    const char *family,
    const char *type,
    const wchar_t *path,
    int priority_tier,
    const char *parser_hint,
    long long size_bytes,
    long long child_count,
    int auto_select
) {
    bof_triage_target_t *target;
    if (g_bof_triage_target_count >= MAX_BOF_TRIAGE_TARGETS) {
        g_bof_triage_target_overflow = 1;
        return;
    }
    target = &g_bof_triage_targets[g_bof_triage_target_count++];
    target->priority_tier = priority_tier;
    target->auto_select = auto_select;
    target->size_bytes = size_bytes;
    target->child_count = child_count;
    target->tool = tool;
    target->family = family;
    target->type = type;
    target->parser_hint = parser_hint;
    copy_wide_path(target->path, path, BL_MAX_PATH_LEN);
}

static int wide_path_token_is_boundary(wchar_t value) {
    return value == 0 || value == L'/' || value == L'\\' || value == L'.' || value == L'_' || value == L'-';
}

static int wide_contains_ascii_token_ci(const wchar_t *text, const char *needle, int needle_len) {
    int i;
    int j;
    int text_len;
    if (!text || !needle || needle_len <= 0) {
        return 0;
    }
    text_len = (int)inline_wcslen(text);
    if (needle_len > text_len) {
        return 0;
    }
    for (i = 0; i <= text_len - needle_len; i++) {
        if (i > 0 && !wide_path_token_is_boundary(text[i - 1])) {
            continue;
        }
        for (j = 0; j < needle_len; j++) {
            if ((wchar_t)ascii_lower((unsigned char)needle[j]) != wide_lower(text[i + j])) {
                break;
            }
        }
        if (j == needle_len && wide_path_token_is_boundary(text[i + needle_len])) {
            return 1;
        }
    }
    return 0;
}

static void print_bof_collection_first(void) {
    int i;
    int printed = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Collect first: credential/session metadata and auth-adjacent configs\n");
    for (i = 0; i < g_bof_triage_target_count; i++) {
        const bof_triage_target_t *target = &g_bof_triage_targets[i];
        if (!target->auto_select) {
            continue;
        }
        if (target->size_bytes < 1024) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   [%d] %s %s %s %lld B\n", target->priority_tier, target->tool, target->family, target->type, target->size_bytes);
        } else if (target->size_bytes < 1024LL * 1024LL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   [%d] %s %s %s %lld.%lld KB\n", target->priority_tier, target->tool, target->family, target->type, target->size_bytes / 1024, ((target->size_bytes % 1024) * 10) / 1024);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   [%d] %s %s %s %lld.%lld MB\n", target->priority_tier, target->tool, target->family, target->type, target->size_bytes / (1024LL * 1024LL), ((target->size_bytes % (1024LL * 1024LL)) * 10) / (1024LL * 1024LL));
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[i]       %S\n", target->path);
        printed++;
    }
    if (!printed) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   none\n");
    }
    for (i = 0, printed = 0; i < g_bof_triage_target_count; i++) {
        const bof_triage_target_t *target = &g_bof_triage_targets[i];
        if (target->priority_tier != 1 || target->auto_select) continue;
        if (!printed) BeaconPrintf(CALLBACK_OUTPUT, "[i] Auth containers requiring review\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   [1] %s %s - auth_container_review\n[i]       %S\n", target->tool, target->family, target->path);
        printed++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]\n");
}

static void print_bof_tier2_group(const char *tool) {
    int i;
    int count = 0;
    int files = 0;
    int dirs = 0;
    int has_config = 0;
    int has_rules = 0;
    int has_sandbox = 0;
    int has_plugins = 0;
    int has_other = 0;
    for (i = 0; i < g_bof_triage_target_count; i++) {
        const bof_triage_target_t *target = &g_bof_triage_targets[i];
        if (!target_tool_is(target, tool) || !target_is_tier2_review(target)) {
            continue;
        }
        count++;
        files += target_is_file(target);
        dirs += target_is_directory(target);
        has_config |= target_family_is(target, "config") || target_family_is(target, "mcp") || target_family_is(target, "mcp_config") ||
            target_family_is(target, "project_config") || target_family_is(target, "project_mcp_config") || target_family_is(target, "permissions");
        has_rules |= target_family_is(target, "rules");
        has_sandbox |= target_family_is(target, "sandbox") || wide_contains_ascii_n_ci(target->path, ".sandbox-secrets", 16);
        has_plugins |= target_family_is(target, "plugins") || target_family_is(target, "extensions") || target_family_is(target, "skills");
        has_other |= !(target_family_is(target, "config") || target_family_is(target, "mcp") || target_family_is(target, "mcp_config") ||
            target_family_is(target, "project_config") || target_family_is(target, "project_mcp_config") || target_family_is(target, "permissions") || target_family_is(target, "rules") ||
            target_family_is(target, "sandbox") || target_family_is(target, "plugins") ||
            target_family_is(target, "extensions") || target_family_is(target, "skills") ||
            wide_contains_ascii_n_ci(target->path, ".sandbox-secrets", 16));
    }
    if (count <= 0) {
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]   [2] %s %s%s%s%s%s %s x%d\n",
        tool,
        has_config ? "config" : "",
        has_rules ? "/rules" : "",
        has_plugins ? "/plugins" : "",
        has_sandbox ? "/sandbox" : "",
        has_other ? "/review" : "",
        dirs == count ? "dirs" : (files == count ? "files" : "artifacts"),
        count
    );
    for (i = 0; i < g_bof_triage_target_count; i++) {
        const bof_triage_target_t *target = &g_bof_triage_targets[i];
        if (target_tool_is(target, tool) && target_is_tier2_review(target)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]       %S\n", target->path);
        }
    }
}

static void print_bof_review_next(void) {
    int i;
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Review next: config, rules, plugins, sandbox state\n");
    for (i = 0; i < g_bof_triage_target_count; i++) {
        int seen = 0;
        int j;
        if (!target_is_tier2_review(&g_bof_triage_targets[i])) {
            continue;
        }
        for (j = 0; j < i; j++) {
            if (target_is_tier2_review(&g_bof_triage_targets[j]) &&
                target_tool_is(&g_bof_triage_targets[j], g_bof_triage_targets[i].tool)) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            print_bof_tier2_group(g_bof_triage_targets[i].tool);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]\n");
}

static void print_bof_session_context(void) {
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
    inline_memset(groups, 0, sizeof(groups));
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Session activity (collect selectively)\n");
    for (i = 0; i < g_bof_triage_target_count; i++) {
        const bof_triage_target_t *target = &g_bof_triage_targets[i];
        int index = -1;
        if (!target_is_session_context(target)) {
            continue;
        }
        for (j = 0; j < group_count; j++) {
            if (target_tool_is(target, groups[j].tool)) {
                index = j;
                break;
            }
        }
        if (index < 0) {
            if (group_count >= 32) {
                continue;
            }
            index = group_count++;
            groups[index].tool = target->tool;
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
            if (best < 0 || groups[i].count > groups[best].count ||
                (groups[i].count == groups[best].count && groups[i].largest > groups[best].largest)) {
                best = i;
            }
        }
        if (best < 0) {
            break;
        }
        {
            int tool_slot = session_tool_slot(groups[best].tool);
            int session_artifacts = tool_slot >= 0 ? g_session_artifact_counts[tool_slot] : 0;
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   [3] %s history/session locations x%d | %d session artifact%s%s\n", groups[best].tool, groups[best].count,
                session_artifacts, session_artifacts == 1 ? "" : "s", g_session_scan_partial ? " (partial scan)" : "");
        }
        for (i = 0; i < g_bof_triage_target_count; i++) {
            const bof_triage_target_t *target = &g_bof_triage_targets[i];
            if (!target_is_session_context(target) || !target_tool_is(target, groups[best].tool)) {
                continue;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[i]       %S\n", target->path);
        }
        groups[best].printed = 1;
        printed++;
    }
    if (!printed) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   none\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]\n");
}

static void print_bof_top_session_files(void) {
    int i;
    int rank = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[i] PRIORITIZED SESSION ARTIFACTS (newest first)%s\n", g_session_scan_partial ? " (partial scan)" : "");
    if (g_top_session_count == 0) BeaconPrintf(CALLBACK_OUTPUT, "[i]   none\n");
    for (i = 0; i < BOF_TOP_SESSION_COUNT; i++) {
        const bof_session_candidate_t *target = &g_top_sessions[i];
        SYSTEMTIME utc;
        char size[32];
        if (!target->tool) continue;
        rank = (i % BOF_TOP_SESSIONS_PER_TOOL) + 1;
        if (target->size_bytes < 1024) BeaconPrintf(CALLBACK_OUTPUT, "[+] [%d] %s | %lld B", rank, target->tool, target->size_bytes);
        else if (target->size_bytes < 1024 * 1024) BeaconPrintf(CALLBACK_OUTPUT, "[+] [%d] %s | %lld.%lld KB", rank, target->tool, target->size_bytes / 1024, ((target->size_bytes % 1024) * 10) / 1024);
        else BeaconPrintf(CALLBACK_OUTPUT, "[+] [%d] %s | %lld.%lld MB", rank, target->tool, target->size_bytes / (1024 * 1024), ((target->size_bytes % (1024 * 1024)) * 10) / (1024 * 1024));
        inline_memset(&utc, 0, sizeof(utc));
        if (KERNEL32$FileTimeToSystemTime(&target->last_write_time, &utc)) BeaconPrintf(CALLBACK_OUTPUT, " | modified %04d-%02d-%02d", utc.wYear, utc.wMonth, utc.wDay);
        BeaconPrintf(CALLBACK_OUTPUT, "\n        %S\n", target->path);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]\n");
}

static void print_bof_low_priority(void) {
    int tier;
    int printed = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Other inventory\n");
    for (tier = 4; tier <= 5; tier++) {
        int i;
        for (i = 0; i < g_bof_triage_target_count; i++) {
            int j;
            int seen = 0;
            int count = 0;
            int dirs = 0;
            int files = 0;
            const char *family = g_bof_triage_targets[i].family;
            if (g_bof_triage_targets[i].priority_tier != tier) {
                continue;
            }
            for (j = 0; j < i; j++) {
                if (g_bof_triage_targets[j].priority_tier == tier && target_family_is(&g_bof_triage_targets[j], family)) {
                    seen = 1;
                    break;
                }
            }
            if (seen) {
                continue;
            }
            for (j = 0; j < g_bof_triage_target_count; j++) {
                const bof_triage_target_t *target = &g_bof_triage_targets[j];
                if (target->priority_tier == tier && target_family_is(target, family)) {
                    count++;
                    dirs += target_is_directory(target);
                    files += target_is_file(target);
                }
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   [%d] %s %s x%d\n", tier, family, dirs == count ? "dirs" : (files == count ? "files" : "artifacts"), count);
            for (j = 0; j < g_bof_triage_target_count; j++) {
                const bof_triage_target_t *target = &g_bof_triage_targets[j];
                if (target->priority_tier == tier && target_family_is(target, family)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[i]       %S\n", target->path);
                }
            }
            printed++;
        }
    }
    if (!printed) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   none\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]\n");
}

static void bof_print_human_size(long long size_bytes) {
    long long unit;
    long long whole;
    long long remainder;
    long long tenths;
    const char *label;
    if (size_bytes < 1024) {
        BeaconPrintf(CALLBACK_OUTPUT, "%lld B", size_bytes);
        return;
    }
    if (size_bytes < 1024LL * 1024LL) {
        unit = 1024;
        label = "KB";
    } else {
        unit = 1024LL * 1024LL;
        label = "MB";
    }
    whole = size_bytes / unit;
    remainder = size_bytes % unit;
    tenths = (remainder * 10 + unit / 2) / unit;
    if (tenths == 10) {
        whole++;
        tenths = 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "%lld.%lld %s", whole, tenths, label);
}

static void print_bof_codex_sqlite_summary(void) {
    int i;
    if (!g_codex_sqlite_check_requested) return;
    BeaconPrintf(CALLBACK_OUTPUT, "[i] CODEX SQLITE DATABASES\n");
    for (i = 0; i < BOF_CODEX_SQLITE_FAMILY_COUNT; i++) {
        const bof_codex_sqlite_family_t *family = &g_codex_sqlite_families[i];
        SYSTEMTIME utc;
        if (g_codex_sqlite_root_missing) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s: absent (0 versions)\n", g_codex_sqlite_family_names[i]);
        } else if (!g_codex_sqlite_root_available) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s: unknown (Codex root unavailable)\n", g_codex_sqlite_family_names[i]);
        } else if (g_codex_sqlite_scan_partial) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s: partial (%d version%s observed)", g_codex_sqlite_family_names[i],
                family->count, family->count == 1 ? "" : "s");
            if (family->has_newest) {
                BeaconPrintf(CALLBACK_OUTPUT, " | newest observed ");
                bof_print_human_size(family->newest_size);
                if (KERNEL32$FileTimeToSystemTime(&family->newest_write_time, &utc))
                    BeaconPrintf(CALLBACK_OUTPUT, " | modified %04d-%02d-%02dT%02d:%02d:%02dZ\n",
                        utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond);
                else
                    BeaconPrintf(CALLBACK_OUTPUT, " | modified unavailable\n");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "\n");
            }
        } else if (family->count == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s: absent (0 versions)\n", g_codex_sqlite_family_names[i]);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s: present (%d version%s) | newest observed ",
                g_codex_sqlite_family_names[i], family->count, family->count == 1 ? "" : "s");
            bof_print_human_size(family->newest_size);
            if (KERNEL32$FileTimeToSystemTime(&family->newest_write_time, &utc))
                BeaconPrintf(CALLBACK_OUTPUT, " | modified %04d-%02d-%02dT%02d:%02d:%02dZ\n",
                    utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond);
            else
                BeaconPrintf(CALLBACK_OUTPUT, " | modified unavailable\n");
        }
        if (family->has_newest) BeaconPrintf(CALLBACK_OUTPUT, "        %S\n", family->newest_path);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]\n");
}

static void print_bof_human_triage_summary(const bl_scan_results_t *results) {
    int i, tools = 0, auth = 0, sessions = 0, session_artifacts = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Blacklight endpoint assessment\n[i]\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] ASSESSMENT SUMMARY\n");
    for (i = 0; i < g_bof_triage_target_count; i++) {
        int j, seen = 0;
        if (target_family_is(&g_bof_triage_targets[i], "auth") && target_is_file(&g_bof_triage_targets[i])) auth++;
        if (target_is_session_context(&g_bof_triage_targets[i])) sessions++;
        for (j = 0; j < i; j++) if (target_tool_is(&g_bof_triage_targets[j], g_bof_triage_targets[i].tool)) { seen = 1; break; }
        if (!seen) tools++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i]   Tools detected:       %d\n", tools);
    if (auth) BeaconPrintf(CALLBACK_OUTPUT, "[+]   Credential stores:    %d file%s\n", auth, auth == 1 ? "" : "s");
    if (sessions) BeaconPrintf(CALLBACK_OUTPUT, "[i]   Session locations:    %d\n", sessions);
    for (i = 0; i < BOF_SESSION_TOOL_COUNT; i++) session_artifacts += g_session_artifact_counts[i];
    if (sessions || g_session_scan_partial) BeaconPrintf(CALLBACK_OUTPUT, "[i]   Session artifacts:    %d%s\n", session_artifacts, g_session_scan_partial ? " (partial scan)" : "");
    BeaconPrintf(CALLBACK_OUTPUT, "%s   Discovery status:     %s\n[i]\n", (g_dynamic_scan_partial || g_bof_triage_target_overflow || g_session_scan_partial) ? "[!]" : "[i]", (g_dynamic_scan_partial || g_bof_triage_target_overflow || g_session_scan_partial) ? "PARTIAL" : "COMPLETE");
    print_bof_codex_sqlite_summary();
    print_bof_collection_first();
    print_bof_review_next();
    print_bof_top_session_files();
    print_bof_session_context();
    print_bof_low_priority();
    if (g_bof_triage_target_overflow) BeaconPrintf(CALLBACK_OUTPUT, "[!] Result storage cap reached at %d artifacts. Results are incomplete.\n", MAX_BOF_TRIAGE_TARGETS);
    if (g_dynamic_scan_partial) BeaconPrintf(CALLBACK_OUTPUT, "[!] Discovery cap reached after %d candidate entries (per-root cap %d; run cap %d). Results are incomplete.\n", g_dynamic_entries_scanned, BOF_DYNAMIC_ROOT_LIMIT, BOF_DYNAMIC_DISCOVERY_LIMIT);
    (void)results;
}

static void bof_emit_triage(const char *tool, const char *family, const char *type, const void *path) {
    const wchar_t *wide_path = (const wchar_t *)path;
    WIN32_FIND_DATAW find_data;
    HANDLE find_handle;
    long long size_bytes = 0;
    long long child_count = 0;
    int priority_tier;
    int sandbox_secret_path;
    int auth_adjacent_config_path;

    inline_memset(&find_data, 0, sizeof(find_data));
    find_handle = KERNEL32$FindFirstFileW(wide_path, &find_data);
    if (find_handle != INVALID_HANDLE_VALUE) {
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            child_count = count_immediate_children(wide_path);
            if (child_count < 0) {
                child_count = 0;
            }
        } else {
            size_bytes = ((long long)find_data.nFileSizeHigh << 32) | find_data.nFileSizeLow;
        }
        KERNEL32$FindClose(find_handle);
    }

    sandbox_secret_path = wide_contains_ascii_n_ci(wide_path, ".sandbox-secrets", 16);
    auth_adjacent_config_path =
        wide_contains_ascii_n_ci(wide_path, ".claude.json", 12) &&
        !wide_contains_ascii_n_ci(wide_path, ".claude/.claude.json", 20) &&
        !wide_contains_ascii_n_ci(wide_path, ".claude\\.claude.json", 20);

    priority_tier = bl_triage_priority_tier(
        family,
        (!sandbox_secret_path &&
         !wide_contains_ascii_n_ci(wide_path, "mcp-needs-auth-cache", 21) && (
            wide_contains_ascii_token_ci(wide_path, "auth", 4) ||
            wide_contains_ascii_token_ci(wide_path, "credential", 10) ||
            wide_contains_ascii_token_ci(wide_path, "token", 5) ||
            wide_contains_ascii_token_ci(wide_path, "secret", 6)
        )) ||
        auth_adjacent_config_path
    );
    if (sandbox_secret_path && priority_tier == 1) {
        priority_tier = 2;
    }

    record_bof_triage_target(
        tool,
        family,
        type,
        wide_path,
        priority_tier,
        bl_triage_parser_hint(family, wide_ends_with_ascii_ci(wide_path, ".db") ||
            wide_ends_with_ascii_ci(wide_path, ".sqlite") || wide_ends_with_ascii_ci(wide_path, ".sqlite3")),
        size_bytes,
        child_count,
        priority_tier == 1 && type && type[0] == 'f'
    );

    if (priority_tier == 1 && type && type[0] == 'f') {
        g_auto_select_count++;
    }
}

static int bof_expand_path(const void *pattern, void *expanded, size_t expanded_size) {
    const wchar_t *wide_pattern = (const wchar_t *)pattern;
    wchar_t *wide_expanded = (wchar_t *)expanded;
    DWORD needed;
    if (!wide_pattern || !wide_expanded || expanded_size == 0) {
        return 0;
    }
    inline_memset(wide_expanded, 0, expanded_size * sizeof(wchar_t));
    needed = KERNEL32$ExpandEnvironmentStringsW(wide_pattern, wide_expanded, (DWORD)expanded_size);
    if (needed == 0 || needed > expanded_size) {
        wide_expanded[0] = L'\0';
        return 0;
    }
    return 1;
}

static int bof_report_path_if_exists(
    const char *tool,
    const char *family,
    const void *path,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    bl_emit_fn emit
) {
    const wchar_t *wide_path = (const wchar_t *)path;
    DWORD attributes;
    const char *type;

    if (!tool || !family || !wide_path || !results || !emit) {
        return 0;
    }

    attributes = KERNEL32$GetFileAttributesW(wide_path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return 0;
    }

    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        type = "directory";
        results->directory_count++;
    } else {
        type = "file";
        results->file_count++;
    }

    results->hit_count++;
    emit(tool, family, type, wide_path);
    return 1;
}

static int bof_path_recorded(const wchar_t *path) {
    int i;
    for (i = 0; i < g_bof_triage_target_count; i++) {
        if (wide_path_compare_ci(g_bof_triage_targets[i].path, path) == 0) return 1;
    }
    return 0;
}

static void bof_report_dynamic_file(
    const char *tool,
    const char *family,
    const wchar_t *path,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters
) {
    if (!bof_path_recorded(path)) {
        bof_report_path_if_exists(tool, family, path, results, filters, bof_emit_triage);
    }
}

static void bof_scan_dynamic_tree(
    const char *tool,
    const wchar_t *directory,
    int depth,
    int include_plan_metadata,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters
) {
    wchar_t search[BL_MAX_PATH_LEN];
    wchar_t child[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW find_data;
    HANDLE find_handle;
    if (depth < 0 || g_dynamic_entries_scanned >= BOF_DYNAMIC_DISCOVERY_LIMIT ||
        g_dynamic_root_entries_scanned >= BOF_DYNAMIC_ROOT_LIMIT) {
        if (g_dynamic_entries_scanned >= BOF_DYNAMIC_DISCOVERY_LIMIT ||
            g_dynamic_root_entries_scanned >= BOF_DYNAMIC_ROOT_LIMIT) g_dynamic_scan_partial = 1;
        return;
    }
    inline_memset(search, 0, sizeof(search));
    if (!build_path(directory, L"\\*", search, BL_MAX_PATH_LEN)) return;
    inline_memset(&find_data, 0, sizeof(find_data));
    find_handle = KERNEL32$FindFirstFileW(search, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) return;
    do {
        if (is_dot_directory(find_data.cFileName)) continue;
        if (g_dynamic_entries_scanned >= BOF_DYNAMIC_DISCOVERY_LIMIT ||
            g_dynamic_root_entries_scanned >= BOF_DYNAMIC_ROOT_LIMIT) { g_dynamic_scan_partial = 1; break; }
        g_dynamic_entries_scanned++;
        g_dynamic_root_entries_scanned++;
        inline_memset(child, 0, sizeof(child));
        if (!build_path(directory, L"\\", child, BL_MAX_PATH_LEN) ||
            !append_wide_in_place(child, find_data.cFileName, BL_MAX_PATH_LEN)) continue;
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (depth > 0) bof_scan_dynamic_tree(tool, child, depth - 1, include_plan_metadata, results, filters);
        } else if (wide_ends_with_ascii_ci(child, "\\.mcp.json")) {
            bof_report_dynamic_file(tool, "mcp", child, results, filters);
        } else if (ascii_equal_n_ci(tool, c_string_len(tool), "claude_code") &&
                   wide_ends_with_ascii_ci(child, "\\sessions-index.json")) {
            bof_report_dynamic_file(tool, "sessions", child, results, filters);
        } else if (include_plan_metadata && wide_ends_with_ascii_ci(find_data.cFileName, ".plan.md")) {
            bof_report_dynamic_file(tool, "plans", child, results, filters);
        }
    } while (KERNEL32$FindNextFileW(find_handle, &find_data));
    KERNEL32$FindClose(find_handle);
}

static int bof_codex_sqlite_family_for_filename(const wchar_t *name, int *family_index, wchar_t *suffix, size_t suffix_capacity) {
    size_t name_length;
    size_t suffix_start;
    size_t suffix_length;
    size_t i;
    int family;
    if (!name || !family_index || !suffix || suffix_capacity == 0 || !wide_ends_with_ascii_ci(name, ".sqlite")) return 0;
    name_length = inline_wcslen(name);
    suffix_start = name_length - 7;
    for (family = 0; family < BOF_CODEX_SQLITE_FAMILY_COUNT; family++) {
        size_t prefix_length = c_string_len(g_codex_sqlite_family_names[family]);
        if (suffix_start <= prefix_length + 1 || name[prefix_length] != L'_') continue;
        for (i = 0; i < prefix_length; i++) {
            if (wide_lower(name[i]) != (wchar_t)ascii_lower((unsigned char)g_codex_sqlite_family_names[family][i])) break;
        }
        if (i != prefix_length) continue;
        suffix_length = suffix_start - prefix_length - 1;
        if (suffix_length == 0 || suffix_length >= suffix_capacity) continue;
        for (i = 0; i < suffix_length; i++) {
            wchar_t digit = name[prefix_length + 1 + i];
            if (digit < L'0' || digit > L'9') break;
            suffix[i] = digit;
        }
        if (i != suffix_length) continue;
        suffix[suffix_length] = L'\0';
        *family_index = family;
        return 1;
    }
    return 0;
}

static int bof_compare_numeric_suffix(const wchar_t *left, const wchar_t *right) {
    size_t left_start = 0;
    size_t right_start = 0;
    size_t left_length;
    size_t right_length;
    size_t i;
    while (left[left_start] == L'0' && left[left_start + 1] != L'\0') left_start++;
    while (right[right_start] == L'0' && right[right_start + 1] != L'\0') right_start++;
    left_length = inline_wcslen(left + left_start);
    right_length = inline_wcslen(right + right_start);
    if (left_length != right_length) return left_length > right_length ? 1 : -1;
    for (i = 0; i < left_length; i++) {
        if (left[left_start + i] != right[right_start + i]) return left[left_start + i] > right[right_start + i] ? 1 : -1;
    }
    return 0;
}

static const wchar_t *bof_codex_path_filename(const wchar_t *path) {
    const wchar_t *cursor;
    const wchar_t *filename = path;
    if (!path) return L"";
    for (cursor = path; *cursor; cursor++) if (*cursor == L'\\' || *cursor == L'/') filename = cursor + 1;
    return filename;
}

static int bof_codex_sqlite_candidate_newer(
    const WIN32_FIND_DATAW *find_data,
    const wchar_t *path,
    const wchar_t *suffix,
    const bof_codex_sqlite_family_t *family
) {
    int time_comparison;
    int suffix_comparison;
    if (find_data->ftLastWriteTime.dwHighDateTime != family->newest_write_time.dwHighDateTime)
        time_comparison = find_data->ftLastWriteTime.dwHighDateTime > family->newest_write_time.dwHighDateTime ? 1 : -1;
    else if (find_data->ftLastWriteTime.dwLowDateTime != family->newest_write_time.dwLowDateTime)
        time_comparison = find_data->ftLastWriteTime.dwLowDateTime > family->newest_write_time.dwLowDateTime ? 1 : -1;
    else time_comparison = 0;
    if (time_comparison != 0) return time_comparison > 0;
    suffix_comparison = bof_compare_numeric_suffix(suffix, family->newest_suffix);
    if (suffix_comparison != 0) return suffix_comparison > 0;
    return wide_path_compare_ci(bof_codex_path_filename(path), bof_codex_path_filename(family->newest_path)) > 0;
}

static void bof_scan_codex_sqlite_files(const wchar_t *profile) {
    wchar_t root[BL_MAX_PATH_LEN];
    wchar_t search[BL_MAX_PATH_LEN];
    wchar_t path[BL_MAX_PATH_LEN];
    wchar_t suffix[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW find_data;
    HANDLE find_handle;
    DWORD attributes;
    DWORD error;
    int family_index;

    g_codex_sqlite_check_requested = 1;
    inline_memset(root, 0, sizeof(root));
    if (!build_path(profile, L"\\.codex", root, BL_MAX_PATH_LEN)) {
        g_codex_sqlite_scan_partial = 1;
        g_dynamic_scan_partial = 1;
        return;
    }
    attributes = KERNEL32$GetFileAttributesW(root);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        error = KERNEL32$GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            g_codex_sqlite_root_missing = 1;
            return;
        }
        g_codex_sqlite_scan_partial = 1;
        g_dynamic_scan_partial = 1;
        return;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        g_codex_sqlite_scan_partial = 1;
        g_dynamic_scan_partial = 1;
        return;
    }
    g_codex_sqlite_root_available = 1;
    inline_memset(search, 0, sizeof(search));
    if (!build_path(root, L"\\*", search, BL_MAX_PATH_LEN)) {
        g_codex_sqlite_scan_partial = 1;
        g_dynamic_scan_partial = 1;
        return;
    }
    inline_memset(&find_data, 0, sizeof(find_data));
    find_handle = KERNEL32$FindFirstFileW(search, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        if (KERNEL32$GetLastError() != ERROR_FILE_NOT_FOUND) {
            g_codex_sqlite_scan_partial = 1;
            g_dynamic_scan_partial = 1;
        }
        return;
    }
    do {
        if (is_dot_directory(find_data.cFileName)) continue;
        if (g_dynamic_entries_scanned >= BOF_DYNAMIC_DISCOVERY_LIMIT ||
            g_dynamic_root_entries_scanned >= BOF_DYNAMIC_ROOT_LIMIT) {
            g_codex_sqlite_scan_partial = 1;
            g_dynamic_scan_partial = 1;
            break;
        }
        g_dynamic_entries_scanned++;
        g_dynamic_root_entries_scanned++;
        if ((find_data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) continue;
        if (!bof_codex_sqlite_family_for_filename(find_data.cFileName, &family_index, suffix, BL_MAX_PATH_LEN)) continue;
        inline_memset(path, 0, sizeof(path));
        if (!build_path(root, L"\\", path, BL_MAX_PATH_LEN) ||
            !append_wide_in_place(path, find_data.cFileName, BL_MAX_PATH_LEN)) {
            g_codex_sqlite_scan_partial = 1;
            g_dynamic_scan_partial = 1;
            continue;
        }
        {
            bof_codex_sqlite_family_t *family = &g_codex_sqlite_families[family_index];
            long long size_bytes = ((long long)find_data.nFileSizeHigh << 32) | find_data.nFileSizeLow;
            family->count++;
            if (!family->has_newest || bof_codex_sqlite_candidate_newer(&find_data, path, suffix, family)) {
                family->has_newest = 1;
                family->newest_size = size_bytes;
                family->newest_write_time = find_data.ftLastWriteTime;
                copy_wide_path(family->newest_suffix, suffix, BL_MAX_PATH_LEN);
                copy_wide_path(family->newest_path, path, BL_MAX_PATH_LEN);
            }
        }
    } while (KERNEL32$FindNextFileW(find_handle, &find_data));
    error = KERNEL32$GetLastError();
    if (error != ERROR_NO_MORE_FILES && !g_codex_sqlite_scan_partial) {
        g_codex_sqlite_scan_partial = 1;
        g_dynamic_scan_partial = 1;
    }
    KERNEL32$FindClose(find_handle);
}

static void bof_scan_dynamic_targets(bl_scan_results_t *results, const bl_scan_filters_t *filters) {
    wchar_t profile[BL_MAX_PATH_LEN];
    wchar_t root[BL_MAX_PATH_LEN];
    wchar_t pattern[BL_MAX_PATH_LEN];
    wchar_t path[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW find_data;
    HANDLE find_handle;
    DWORD needed;
    inline_memset(profile, 0, sizeof(profile));
    needed = KERNEL32$ExpandEnvironmentStringsW(L"%USERPROFILE%", profile, BL_MAX_PATH_LEN);
    if (needed == 0 || needed > BL_MAX_PATH_LEN || wide_contains_ascii_n_ci(profile, "%USERPROFILE%", 13)) {
        if (bl_target_allowed("codex", filters)) {
            g_codex_sqlite_check_requested = 1;
            g_codex_sqlite_scan_partial = 1;
            g_dynamic_scan_partial = 1;
        }
        return;
    }

    if (bl_target_allowed("codex", filters)) {
        inline_memset(root, 0, sizeof(root));
        g_dynamic_root_entries_scanned = 0;
        bof_scan_codex_sqlite_files(profile);
        inline_memset(root, 0, sizeof(root));
        g_dynamic_root_entries_scanned = 0;
        if (build_path(profile, L"\\.codex\\rules", root, BL_MAX_PATH_LEN) &&
            build_path(root, L"\\*.rules", pattern, BL_MAX_PATH_LEN)) {
            inline_memset(&find_data, 0, sizeof(find_data));
            find_handle = KERNEL32$FindFirstFileW(pattern, &find_data);
            if (find_handle != INVALID_HANDLE_VALUE) {
                do {
                    if (g_dynamic_entries_scanned >= BOF_DYNAMIC_DISCOVERY_LIMIT ||
                        g_dynamic_root_entries_scanned >= BOF_DYNAMIC_ROOT_LIMIT) { g_dynamic_scan_partial = 1; break; }
                    g_dynamic_entries_scanned++;
                    g_dynamic_root_entries_scanned++;
                    if ((find_data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) continue;
                    inline_memset(path, 0, sizeof(path));
                    if (build_path(root, L"\\", path, BL_MAX_PATH_LEN) &&
                        append_wide_in_place(path, find_data.cFileName, BL_MAX_PATH_LEN)) {
                        bof_report_dynamic_file("codex", "rules", path, results, filters);
                    }
                } while (KERNEL32$FindNextFileW(find_handle, &find_data));
                KERNEL32$FindClose(find_handle);
            }
        }
    }
    inline_memset(root, 0, sizeof(root));
    g_dynamic_root_entries_scanned = 0;
    if (build_path(profile, L"\\.claude\\projects", root, BL_MAX_PATH_LEN))
        bof_scan_dynamic_tree("claude_code", root, BOF_DYNAMIC_DISCOVERY_MAX_DEPTH, 0, results, filters);
    inline_memset(root, 0, sizeof(root));
    g_dynamic_root_entries_scanned = 0;
    if (build_path(profile, L"\\.cursor\\projects", root, BL_MAX_PATH_LEN))
        bof_scan_dynamic_tree("cursor", root, BOF_DYNAMIC_DISCOVERY_MAX_DEPTH, 0, results, filters);
    inline_memset(root, 0, sizeof(root));
    g_dynamic_root_entries_scanned = 0;
    if (build_path(profile, L"\\.cursor\\plans", root, BL_MAX_PATH_LEN))
        bof_scan_dynamic_tree("cursor", root, 0, 1, results, filters);
}

void go(char *args, unsigned long alen) {
    bl_scan_results_t results;
    bl_scan_filters_t filters;

    (void)args;
    (void)alen;
    inline_memset(&results, 0, sizeof(results));
    inline_memset(&filters, 0, sizeof(filters));
    g_bof_triage_target_count = 0;
    g_bof_triage_target_overflow = 0;
    inline_memset(g_codex_sqlite_families, 0, sizeof(g_codex_sqlite_families));
    g_codex_sqlite_check_requested = 0;
    g_codex_sqlite_root_available = 0;
    g_codex_sqlite_root_missing = 0;
    g_codex_sqlite_scan_partial = 0;

    filters.max_depth = 1;
    filters.triage = 1;
    g_auto_select_count = 0;
    g_dynamic_entries_scanned = 0;
    g_dynamic_root_entries_scanned = 0;
    g_dynamic_scan_partial = 0;
    g_child_entries_scanned = 0;
    g_child_scan_partial = 0;

    bl_scan_static_targets(
        BL_STATIC_TARGETS,
        BL_STATIC_TARGETS_COUNT,
        &results,
        &filters,
        bof_expand_path,
        bof_report_path_if_exists,
        bof_emit_triage
    );
    bof_scan_dynamic_targets(&results, &filters);
    scan_session_candidates();
    print_bof_human_triage_summary(&results);
}
