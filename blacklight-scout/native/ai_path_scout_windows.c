/*
 * Blacklight Scout - standalone Windows executable
 *
 * Standalone executable using the same static catalog and filter core as the
 * BOF. Emits one bounded human endpoint assessment; machine discovery remains
 * available through the POSIX loaders.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define BLACKLIGHT_SCOUT_WINDOWS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <wchar.h>
#include <windows.h>

#include "../catalog/static_targets_generated.h"
#include "ai_path_scout_core.h"

static int g_triage_max_depth = 1;
static int g_auto_select_count = 0;

#ifndef BL_MAX_OPERATOR_TARGETS
#define BL_MAX_OPERATOR_TARGETS 256
#endif
#define BL_SCOUT_VERSION "0.2.0"
#define BL_SESSION_SCAN_LIMIT 10000
#define BL_SESSION_SCAN_MAX_DEPTH 32
#define BL_SESSION_TOOL_COUNT 5
#define BL_TOP_SESSIONS_PER_TOOL 3
#define BL_TOP_SESSION_COUNT (BL_SESSION_TOOL_COUNT * BL_TOP_SESSIONS_PER_TOOL)
#define BL_MAX_CHILD_COUNT_DEPTH 4
#define BL_CHILD_ENTRY_SCAN_LIMIT 10000
#define BL_INSPECTED_FILE_LIMIT 64
#define BL_TOTAL_INSPECTION_BYTE_LIMIT (32LL * 1024LL * 1024LL)
#define BL_DYNAMIC_DISCOVERY_LIMIT 5000
#define BL_DYNAMIC_ROOT_LIMIT (BL_DYNAMIC_DISCOVERY_LIMIT / 4)
#define BL_DYNAMIC_DISCOVERY_MAX_DEPTH 6

static FILE *g_output_file = NULL;

static FILE *bl_open_new_output_file(const char *path) {
    HANDLE handle;
    int descriptor;
    FILE *stream;

    handle = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    descriptor = _open_osfhandle((intptr_t)handle, _O_WRONLY | _O_BINARY);
    if (descriptor < 0) {
        CloseHandle(handle);
        return NULL;
    }
    stream = _fdopen(descriptor, "wb");
    if (!stream) {
        _close(descriptor);
    }
    return stream;
}

static int bl_write_handle_or_file(FILE *stream, const char *text) {
    HANDLE handle;
    DWORD written = 0;
    DWORD total = 0;
    DWORD len;
    if (!text) {
        return 0;
    }
    len = (DWORD)strlen(text);
    if (g_output_file && stream != stderr) {
        fputs(text, g_output_file);
        return (int)len;
    }
    handle = GetStdHandle(stream == stderr ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    if (handle && handle != INVALID_HANDLE_VALUE) {
        while (total < len) {
            if (!WriteFile(handle, text + total, len - total, &written, NULL) || written == 0) {
                break;
            }
            total += written;
        }
        if (total == len) {
            return (int)len;
        }
    }
    fputs(text + total, stream == stderr ? stderr : stdout);
    fflush(stream == stderr ? stderr : stdout);
    return (int)len;
}

static int bl_vprintf_to(FILE *stream, const char *fmt, va_list args) {
    char buffer[4096];
    int needed;
    va_list copy;
    va_copy(copy, args);
    needed = vsnprintf(buffer, sizeof(buffer), fmt, copy);
    va_end(copy);
    if (needed < 0) {
        return needed;
    }
    if (needed < (int)sizeof(buffer)) {
        return bl_write_handle_or_file(stream, buffer);
    }
    {
        char *dynamic_buffer = (char *)malloc((size_t)needed + 1);
        int written;
        if (!dynamic_buffer) {
            return -1;
        }
        vsnprintf(dynamic_buffer, (size_t)needed + 1, fmt, args);
        written = bl_write_handle_or_file(stream, dynamic_buffer);
        free(dynamic_buffer);
        return written;
    }
}

static int bl_printf(const char *fmt, ...) {
    int written;
    va_list args;
    va_start(args, fmt);
    written = bl_vprintf_to(stdout, fmt, args);
    va_end(args);
    return written;
}

static int bl_fprintf(FILE *stream, const char *fmt, ...) {
    int written;
    va_list args;
    va_start(args, fmt);
    written = bl_vprintf_to(stream, fmt, args);
    va_end(args);
    return written;
}

static int bl_putchar(int ch) {
    char text[2];
    text[0] = (char)ch;
    text[1] = '\0';
    return bl_write_handle_or_file(stdout, text);
}

#define printf bl_printf
#define fprintf bl_fprintf
#define putchar bl_putchar

static int bl_print_wide_utf8(const wchar_t *value) {
    char *utf8;
    int needed;
    int written;
    if (!value) return 0;
    needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, NULL, 0, NULL, NULL);
    if (needed <= 0) return -1;
    utf8 = (char *)malloc((size_t)needed);
    if (!utf8) return -1;
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, utf8, needed, NULL, NULL)) {
        free(utf8);
        return -1;
    }
    written = bl_write_handle_or_file(stdout, utf8);
    free(utf8);
    return written;
}

typedef struct {
    int priority_tier;
    int auto_select;
    long long size_bytes;
    long long child_count;
    const char *tool;
    const char *family;
    const char *type;
    const char *parser_hint;
    long long record_count;
    long long malformed_record_count;
    int credential_key_type_count;
    int config_setting_count;
    int connector_definition_count;
    int rule_count;
    int allow_rule_count;
    int deny_rule_count;
    int permission_setting_count;
    int token_like_field_count;
    int refresh_field_count;
    int account_metadata_field_count;
    int expiration_field_count;
    int auth_state_field_count;
    int analysis_truncated;
    int child_count_partial;
    int child_count_unavailable;
    int child_count_disabled;
    DWORD file_attributes;
    FILETIME last_write_time;
    char safe_signals[512];
    wchar_t path[BL_MAX_PATH_LEN];
} bl_operator_target_t;

static bl_operator_target_t g_operator_targets[BL_MAX_OPERATOR_TARGETS];
static int g_operator_target_count = 0;
static int g_operator_target_overflow = 0;

typedef struct {
    const char *tool;
    long long size_bytes;
    FILETIME last_write_time;
    wchar_t path[BL_MAX_PATH_LEN];
} bl_session_candidate_t;

static bl_session_candidate_t g_top_sessions[BL_TOP_SESSION_COUNT];
static int g_top_session_count = 0;
static bl_session_candidate_t g_largest_sessions[BL_TOP_SESSION_COUNT];
static int g_largest_session_count = 0;
static int session_candidate_larger(const bl_session_candidate_t *left, const bl_session_candidate_t *right);
static void retain_session_candidate(bl_session_candidate_t *sessions, int *session_count, int base, const bl_session_candidate_t *candidate, int largest_first);
static int g_session_artifact_counts[BL_SESSION_TOOL_COUNT];
static int g_session_entries_scanned = 0;
static int g_session_scan_partial = 0;
static int g_session_scan_stop = 0;
static int g_child_entries_scanned = 0;
static int g_inspection_files = 0;
static long long g_inspection_bytes = 0;
static int g_inspection_budget_exhausted = 0;
static int g_dynamic_entries_scanned = 0;
static int g_dynamic_root_entries_scanned = 0;
static int g_dynamic_root_limit = BL_DYNAMIC_ROOT_LIMIT;
static int g_dynamic_discovery_limit = BL_DYNAMIC_DISCOVERY_LIMIT;
static int g_dynamic_scan_partial = 0;

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
    text_len = (int)wcslen(text);
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

static int wide_contains_ascii_token_ci(const wchar_t *text, const char *needle, int needle_len);

static long long count_directory_children(const wchar_t *path, int depth, int *partial, int *unavailable) {
    wchar_t search_path[BL_MAX_PATH_LEN + 3];
    wchar_t child_path[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW data;
    HANDLE handle;
    size_t len;
    long long count = 0;
    if (partial) *partial = 0;
    if (unavailable) *unavailable = 0;
    if (!path || depth <= 0) return 0;
    if (g_child_entries_scanned >= BL_CHILD_ENTRY_SCAN_LIMIT) {
        if (partial) *partial = 1;
        if (unavailable) *unavailable = 1;
        return 0;
    }
    len = wcslen(path);
    if (len + 3 >= sizeof(search_path) / sizeof(search_path[0])) {
        if (unavailable) *unavailable = 1;
        return 0;
    }
    wcscpy(search_path, path);
    if (len > 0 && search_path[len - 1] != L'\\' && search_path[len - 1] != L'/') {
        search_path[len++] = L'\\';
        search_path[len] = L'\0';
    }
    search_path[len++] = L'*';
    search_path[len] = L'\0';
    handle = FindFirstFileW(search_path, &data);
    if (handle == INVALID_HANDLE_VALUE) {
        if (unavailable) *unavailable = 1;
        return 0;
    }
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }
        if (g_child_entries_scanned >= BL_CHILD_ENTRY_SCAN_LIMIT) {
            if (partial) *partial = 1;
            break;
        }
        g_child_entries_scanned++;
        count++;
        if (depth <= 1 || (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (wcslen(path) + wcslen(data.cFileName) + 2 >= sizeof(child_path) / sizeof(child_path[0])) {
            if (partial) *partial = 1;
            continue;
        }
        wcscpy(child_path, path);
        if (child_path[wcslen(child_path) - 1] != L'\\' && child_path[wcslen(child_path) - 1] != L'/') {
            wcscat(child_path, L"\\");
        }
        wcscat(child_path, data.cFileName);
        {
            int child_partial = 0;
            int child_unavailable = 0;
            long long nested = count_directory_children(child_path, depth - 1, &child_partial, &child_unavailable);
            count += nested;
            if ((child_partial || child_unavailable) && partial) *partial = 1;
            if (g_child_entries_scanned >= BL_CHILD_ENTRY_SCAN_LIMIT) break;
        }
    } while (FindNextFileW(handle, &data));
    if (GetLastError() != ERROR_NO_MORE_FILES && partial) *partial = 1;
    FindClose(handle);
    return count;
}

static bl_operator_target_t *record_operator_target(
    const char *tool,
    const char *family,
    const char *type,
    const wchar_t *path,
    int priority_tier,
    const char *parser_hint,
    long long size_bytes,
    long long child_count,
    int auto_select,
    int child_count_partial,
    int child_count_unavailable,
    DWORD file_attributes
) {
    bl_operator_target_t *target;
    if (g_operator_target_count >= BL_MAX_OPERATOR_TARGETS || !path) {
        g_operator_target_overflow = 1;
        return NULL;
    }
    target = &g_operator_targets[g_operator_target_count++];
    memset(target, 0, sizeof(*target));
    target->priority_tier = priority_tier;
    target->auto_select = auto_select;
    target->size_bytes = size_bytes;
    target->child_count = child_count;
    target->tool = tool;
    target->family = family;
    target->type = type;
    target->parser_hint = parser_hint;
    target->child_count_partial = child_count_partial;
    target->child_count_unavailable = child_count_unavailable;
    target->child_count_disabled = strcmp(type, "directory") == 0 && g_triage_max_depth == 0;
    target->file_attributes = file_attributes;
    {
        int i;
        for (i = 0; i < BL_MAX_PATH_LEN - 1 && path[i] != L'\0'; i++) {
            target->path[i] = path[i] == L'/' ? L'\\' : path[i];
        }
        target->path[i] = L'\0';
    }
    return target;
}

static int wide_path_compare_ordinal_ascii_ci(const wchar_t *left, const wchar_t *right) {
    size_t i = 0;
    while (left[i] && right[i]) {
        wchar_t a = left[i] >= L'a' && left[i] <= L'z' ? left[i] - (L'a' - L'A') : left[i];
        wchar_t b = right[i] >= L'a' && right[i] <= L'z' ? right[i] - (L'a' - L'A') : right[i];
        if (a != b) return a < b ? -1 : 1;
        i++;
    }
    if (left[i] == right[i]) return 0;
    return left[i] ? 1 : -1;
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
    return wide_path_compare_ordinal_ascii_ci(a->path, b->path);
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

static int wide_ends_with_ascii_ci(const wchar_t *text, const char *suffix) {
    size_t text_len;
    size_t suffix_len;
    size_t i;
    if (!text || !suffix) return 0;
    text_len = wcslen(text);
    suffix_len = strlen(suffix);
    if (suffix_len > text_len) return 0;
    for (i = 0; i < suffix_len; i++) {
        if (wide_lower(text[text_len - suffix_len + i]) != (wchar_t)ascii_lower((unsigned char)suffix[i])) return 0;
    }
    return 1;
}

static int session_file_recognized(const char *tool, const wchar_t *path) {
    if (strcmp(tool, "codex") == 0) {
        return wide_contains_ascii_n_ci(path, "sessions", 8) && wide_ends_with_ascii_ci(path, ".jsonl");
    }
    if (strcmp(tool, "claude_code") == 0) {
        return (wide_contains_ascii_n_ci(path, "sessions", 8) || wide_contains_ascii_n_ci(path, "projects", 8)) &&
            wide_ends_with_ascii_ci(path, ".jsonl");
    }
    if (strcmp(tool, "cursor") == 0) {
        return wide_ends_with_ascii_ci(path, "store.db") ||
            (wide_contains_ascii_n_ci(path, "agent-transcripts", 17) && wide_ends_with_ascii_ci(path, ".jsonl"));
    }
    if (strcmp(tool, "antigravity_cli") == 0) {
        return wide_ends_with_ascii_ci(path, "transcript_full.jsonl") ||
            wide_ends_with_ascii_ci(path, "transcript.jsonl") ||
            wide_ends_with_ascii_ci(path, "conversation_summaries.db") ||
            (wide_contains_ascii_n_ci(path, "conversations", 13) && wide_ends_with_ascii_ci(path, ".db"));
    }
    if (strcmp(tool, "grok") == 0) {
        return wide_ends_with_ascii_ci(path, "updates.jsonl");
    }
    return 0;
}

static int session_candidate_better(const bl_session_candidate_t *left, const bl_session_candidate_t *right) {
    int time_cmp;
    int text_cmp;
    time_cmp = CompareFileTime(&left->last_write_time, &right->last_write_time);
    if (time_cmp != 0) return time_cmp > 0;
    if (left->size_bytes != right->size_bytes) return left->size_bytes > right->size_bytes;
    text_cmp = strcmp(left->tool, right->tool);
    if (text_cmp != 0) return text_cmp < 0;
    return _wcsicmp(left->path, right->path) < 0;
}

static int session_tool_slot(const char *tool) {
    if (strcmp(tool, "codex") == 0) return 0;
    if (strcmp(tool, "claude_code") == 0) return 1;
    if (strcmp(tool, "cursor") == 0) return 2;
    if (strcmp(tool, "antigravity_cli") == 0) return 3;
    if (strcmp(tool, "grok") == 0) return 4;
    return -1;
}

static void consider_session_candidate(const char *tool, const wchar_t *path, const WIN32_FIND_DATAW *data) {
    bl_session_candidate_t candidate;
    int tool_slot;
    int base;
    int insert = -1;
    int i;
    if (!tool || !path || !data || !session_file_recognized(tool, path)) return;
    tool_slot = session_tool_slot(tool);
    if (tool_slot < 0) return;
    g_session_artifact_counts[tool_slot]++;
    base = tool_slot * BL_TOP_SESSIONS_PER_TOOL;
    memset(&candidate, 0, sizeof(candidate));
    candidate.tool = tool;
    candidate.size_bytes = ((long long)data->nFileSizeHigh << 32) | data->nFileSizeLow;
    candidate.last_write_time = data->ftLastWriteTime;
    wcsncpy(candidate.path, path, BL_MAX_PATH_LEN - 1);
    for (i = 0; i < BL_TOP_SESSIONS_PER_TOOL; i++) {
        if (g_top_sessions[base + i].tool && _wcsicmp(g_top_sessions[base + i].path, path) == 0) return;
        if (insert < 0 && (!g_top_sessions[base + i].tool || session_candidate_better(&candidate, &g_top_sessions[base + i]))) insert = i;
    }
    if (insert < 0) {
        retain_session_candidate(g_largest_sessions, &g_largest_session_count, base, &candidate, 1);
        return;
    }
    if (!g_top_sessions[base + BL_TOP_SESSIONS_PER_TOOL - 1].tool) g_top_session_count++;
    for (i = BL_TOP_SESSIONS_PER_TOOL - 1; i > insert; i--) g_top_sessions[base + i] = g_top_sessions[base + i - 1];
    g_top_sessions[base + insert] = candidate;
    retain_session_candidate(g_largest_sessions, &g_largest_session_count, base, &candidate, 1);
}

static void walk_session_files(const char *tool, const wchar_t *directory, int depth) {
    wchar_t search[BL_MAX_PATH_LEN];
    wchar_t child[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW data;
    HANDLE handle;
    size_t length;
    if (g_session_scan_stop) return;
    if (depth > BL_SESSION_SCAN_MAX_DEPTH) {
        g_session_scan_partial = 1;
        return;
    }
    length = wcslen(directory);
    if (length + 3 >= BL_MAX_PATH_LEN) {
        g_session_scan_partial = 1;
        return;
    }
    wcscpy(search, directory);
    if (length && search[length - 1] != L'\\' && search[length - 1] != L'/') search[length++] = L'\\';
    search[length++] = L'*';
    search[length] = L'\0';
    handle = FindFirstFileW(search, &data);
    if (handle == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) g_session_scan_partial = 1;
        return;
    }
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        if (g_session_entries_scanned >= BL_SESSION_SCAN_LIMIT) {
            g_session_scan_partial = 1;
            g_session_scan_stop = 1;
            break;
        }
        g_session_entries_scanned++;
        if (length + wcslen(data.cFileName) + 1 >= BL_MAX_PATH_LEN) {
            g_session_scan_partial = 1;
            continue;
        }
        wcscpy(child, directory);
        if (length && child[wcslen(child) - 1] != L'\\' && child[wcslen(child) - 1] != L'/') wcscat(child, L"\\");
        wcscat(child, data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) walk_session_files(tool, child, depth + 1);
        else consider_session_candidate(tool, child, &data);
    } while (!g_session_scan_stop && FindNextFileW(handle, &data));
    if (!g_session_scan_stop && GetLastError() != ERROR_NO_MORE_FILES) g_session_scan_partial = 1;
    FindClose(handle);
}

static int target_can_contain_sessions(const bl_operator_target_t *target) {
    if (!target || strcmp(target->type, "directory") != 0 ||
        (target->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return 0;
    if (strcmp(target->family, "sessions") == 0 || strcmp(target->family, "history") == 0) return 1;
    return strcmp(target->family, "workspace") == 0 &&
        (strcmp(target->tool, "claude_code") == 0 || strcmp(target->tool, "cursor") == 0);
}

static int session_root_seen_before(int index, const bl_operator_target_t *target) {
    int i;
    for (i = 0; i < index; i++) {
        if (target_can_contain_sessions(&g_operator_targets[i]) &&
            strcmp(g_operator_targets[i].tool, target->tool) == 0 &&
            _wcsicmp(g_operator_targets[i].path, target->path) == 0) return 1;
    }
    return 0;
}

static void scan_session_candidates(void) {
    int i;
    memset(g_top_sessions, 0, sizeof(g_top_sessions));
    memset(g_largest_sessions, 0, sizeof(g_largest_sessions));
    memset(g_session_artifact_counts, 0, sizeof(g_session_artifact_counts));
    g_top_session_count = 0;
    g_largest_session_count = 0;
    g_session_entries_scanned = 0;
    g_session_scan_partial = 0;
    g_session_scan_stop = 0;
    for (i = 0; i < g_operator_target_count && !g_session_scan_stop; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (target_can_contain_sessions(target)) {
            if (!session_root_seen_before(i, target)) walk_session_files(target->tool, target->path, 0);
        } else if (strcmp(target->type, "file") == 0 && session_file_recognized(target->tool, target->path)) {
            WIN32_FIND_DATAW data;
            HANDLE handle = FindFirstFileW(target->path, &data);
            if (handle != INVALID_HANDLE_VALUE) {
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    consider_session_candidate(target->tool, target->path, &data);
                }
                FindClose(handle);
            } else {
                g_session_scan_partial = 1;
            }
        }
    }
}

static int session_candidate_larger(const bl_session_candidate_t *left, const bl_session_candidate_t *right) {
    int time_cmp;
    if (left->size_bytes != right->size_bytes) return left->size_bytes > right->size_bytes;
    time_cmp = CompareFileTime(&left->last_write_time, &right->last_write_time);
    if (time_cmp != 0) return time_cmp > 0;
    return _wcsicmp(left->path, right->path) < 0;
}

static void retain_session_candidate(
    bl_session_candidate_t *sessions,
    int *session_count,
    int base,
    const bl_session_candidate_t *candidate,
    int largest_first
) {
    int insert = -1;
    int i;
    for (i = 0; i < BL_TOP_SESSIONS_PER_TOOL; i++) {
        if (sessions[base + i].tool && _wcsicmp(sessions[base + i].path, candidate->path) == 0) return;
        if (insert < 0 && (!sessions[base + i].tool ||
            (largest_first ? session_candidate_larger(candidate, &sessions[base + i]) : session_candidate_better(candidate, &sessions[base + i])))) insert = i;
    }
    if (insert < 0) return;
    if (!sessions[base + BL_TOP_SESSIONS_PER_TOOL - 1].tool) (*session_count)++;
    for (i = BL_TOP_SESSIONS_PER_TOOL - 1; i > insert; i--) sessions[base + i] = sessions[base + i - 1];
    sessions[base + insert] = *candidate;
}

static int ascii_key_boundary(int value) {
    return value == 0 || !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
        (value >= '0' && value <= '9') || value == '_');
}

static int ascii_contains_key_ci(const char *text, const char *needle) {
    size_t i;
    size_t needle_len = strlen(needle);
    for (i = 0; text && text[i]; i++) {
        size_t j;
        if (i > 0 && !ascii_key_boundary((unsigned char)text[i - 1])) continue;
        for (j = 0; j < needle_len && text[i + j]; j++) {
            if (ascii_lower((unsigned char)text[i + j]) != ascii_lower((unsigned char)needle[j])) break;
        }
        if (j == needle_len && ascii_key_boundary((unsigned char)text[i + j])) return 1;
    }
    return 0;
}

static void append_safe_signal(bl_operator_target_t *target, const char *label, const char *value) {
    size_t used;
    size_t needed;
    if (!target || !label || !value || !*value) return;
    used = strlen(target->safe_signals);
    needed = strlen(label) + strlen(value) + (used ? 2 : 0) + 2;
    if (used + needed >= sizeof(target->safe_signals)) return;
    if (used) strcat(target->safe_signals, ", ");
    strcat(target->safe_signals, label);
    strcat(target->safe_signals, "=");
    strcat(target->safe_signals, value);
}

static void count_assignment_signal(bl_operator_target_t *target, const char *text, const char *key) {
    const char *cursor = text;
    size_t key_len = strlen(key);
    while (cursor && *cursor) {
        size_t i;
        for (i = 0; cursor[i] && i < key_len; i++) {
            if (ascii_lower((unsigned char)cursor[i]) != ascii_lower((unsigned char)key[i])) break;
        }
        if (i == key_len) {
            const char *value = cursor + key_len;
            int length = 0;
            if ((cursor > text && !ascii_key_boundary((unsigned char)cursor[-1])) ||
                !ascii_key_boundary((unsigned char)*value)) {
                cursor++;
                continue;
            }
            while (*value == ' ' || *value == '\t' || *value == '"' || *value == '\'' || *value == ':' || *value == '=') value++;
            while (length < 80 && ((value[length] >= 'a' && value[length] <= 'z') ||
                   (value[length] >= 'A' && value[length] <= 'Z') ||
                   (value[length] >= '0' && value[length] <= '9') || value[length] == '_' ||
                   value[length] == '-' || value[length] == '.')) {
                length++;
            }
            if (length > 0) {
                target->config_setting_count++;
            }
            return;
        }
        cursor++;
    }
}

static void extract_project_trust_signals(bl_operator_target_t *target, const char *text) {
    const char *prefix = "[projects.";
    size_t prefix_len = strlen(prefix);
    const char *cursor = text;
    int project_count = 0;
    int trusted_count = 0;
    while (cursor && *cursor) {
        size_t i;
        for (i = 0; i < prefix_len && cursor[i]; i++) {
            if (ascii_lower((unsigned char)cursor[i]) != ascii_lower((unsigned char)prefix[i])) break;
        }
        if (i == prefix_len) {
            project_count++;
            cursor += prefix_len;
            continue;
        }
        cursor++;
    }
    cursor = text;
    while (cursor && *cursor) {
        size_t j;
        const char *needle = "trust_level";
        size_t needle_len = 11;
        for (j = 0; j < needle_len && cursor[j]; j++) {
            if (ascii_lower((unsigned char)cursor[j]) != needle[j]) break;
        }
        if (j == needle_len && (cursor == text || ascii_key_boundary((unsigned char)cursor[-1])) &&
            ascii_key_boundary((unsigned char)cursor[needle_len])) {
            const char *value = cursor + needle_len;
            int length = 0;
            char value_text[81];
            while (*value == ' ' || *value == '\t' || *value == '"' || *value == '\'' || *value == ':' || *value == '=') value++;
            while (length < 80 && ((value[length] >= 'a' && value[length] <= 'z') ||
                   (value[length] >= 'A' && value[length] <= 'Z') ||
                   (value[length] >= '0' && value[length] <= '9') || value[length] == '_' ||
                   value[length] == '-' || value[length] == '.')) {
                value_text[length] = (char)ascii_lower((unsigned char)value[length]);
                length++;
            }
            value_text[length] = '\0';
            if (length == 7 && memcmp(value_text, "trusted", 7) == 0) trusted_count++;
            cursor = value + (length > 0 ? length : 1);
            continue;
        }
        cursor++;
    }
    if (project_count > 0) {
        char count_text[24];
        snprintf(count_text, sizeof(count_text), "%d", project_count);
        append_safe_signal(target, "projects", count_text);
    }
    if (trusted_count > 0) {
        char count_text[24];
        snprintf(count_text, sizeof(count_text), "%d", trusted_count);
        append_safe_signal(target, "trusted", count_text);
    }
}

static void extract_mcp_signals(bl_operator_target_t *target, const char *text) {
    const char *prefix = "[mcp_servers.";
    size_t prefix_len = strlen(prefix);
    const char *cursor = text;
    int count = 0;
    while (cursor && *cursor) {
        size_t i;
        for (i = 0; i < prefix_len && cursor[i]; i++) {
            if (ascii_lower((unsigned char)cursor[i]) != ascii_lower((unsigned char)prefix[i])) break;
        }
        if (i == prefix_len) {
            int length = 0;
            const char *value = cursor + prefix_len;
            while (length < 64 && ((value[length] >= 'a' && value[length] <= 'z') ||
                   (value[length] >= 'A' && value[length] <= 'Z') ||
                   (value[length] >= '0' && value[length] <= '9') || value[length] == '_' ||
                   value[length] == '-' || value[length] == '.')) {
                length++;
            }
            if (length > 0 && value[length] == ']') count++;
            cursor = value + length;
        } else {
            cursor++;
        }
    }
    if (count > 0) {
        char count_text[24];
        snprintf(count_text, sizeof(count_text), "%d", count);
        append_safe_signal(target, "mcp_definitions", count_text);
        target->connector_definition_count += count;
    }
}

static int family_is_auth(const char *family) {
    return family && (strcmp(family, "auth") == 0 || strcmp(family, "credential_metadata") == 0);
}

static int family_is_session(const char *family) {
    return family && (strcmp(family, "sessions") == 0 || strcmp(family, "history") == 0 || strcmp(family, "transcripts") == 0);
}

static int family_is_config(const char *family) {
    if (!family) return 0;
    return strcmp(family, "config") == 0 || strcmp(family, "mcp") == 0 || strcmp(family, "mcp_config") == 0 ||
        strcmp(family, "project_config") == 0 || strcmp(family, "project_mcp_config") == 0 ||
        strcmp(family, "rules") == 0 || strcmp(family, "sandbox") == 0 || strcmp(family, "permissions") == 0 ||
        strcmp(family, "plugins") == 0 || strcmp(family, "extensions") == 0 || strcmp(family, "skills") == 0;
}

static int path_has_inspectable_extension(const wchar_t *path) {
    return wide_ends_with_ascii_ci(path, ".json") || wide_ends_with_ascii_ci(path, ".jsonl") ||
        wide_ends_with_ascii_ci(path, ".toml") || wide_ends_with_ascii_ci(path, ".rules") ||
        wide_ends_with_ascii_ci(path, ".txt");
}

static int path_is_sqlite(const wchar_t *path) {
    return wide_ends_with_ascii_ci(path, ".db") || wide_ends_with_ascii_ci(path, ".sqlite") ||
        wide_ends_with_ascii_ci(path, ".sqlite3");
}

static int count_known_key_types(const char *text, const char **keys, int key_count) {
    int i;
    int count = 0;
    for (i = 0; i < key_count; i++) {
        if (ascii_contains_key_ci(text, keys[i])) count++;
    }
    return count;
}

static int ascii_span_contains_ci(const char *text, size_t text_length, const char *needle) {
    size_t i;
    size_t needle_length = strlen(needle);
    if (!text || !needle || needle_length == 0 || needle_length > text_length) return 0;
    for (i = 0; i + needle_length <= text_length; i++) {
        size_t j;
        for (j = 0; j < needle_length; j++) {
            if (ascii_lower((unsigned char)text[i + j]) != ascii_lower((unsigned char)needle[j])) break;
        }
        if (j == needle_length) return 1;
    }
    return 0;
}

static void count_rule_metadata(bl_operator_target_t *target, const char *text) {
    const char *cursor = text;
    while (cursor && *cursor) {
        const char *line = cursor;
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        while (length > 0 && (*line == ' ' || *line == '\t' || *line == '\r')) { line++; length--; }
        if (length >= 3 && (unsigned char)line[0] == 0xef && (unsigned char)line[1] == 0xbb && (unsigned char)line[2] == 0xbf) {
            line += 3;
            length -= 3;
        }
        if (length > 0 && *line != '#' && !(length > 1 && line[0] == '/' && line[1] == '/')) {
            target->rule_count++;
            if ((length >= 5 && ascii_lower((unsigned char)line[0]) == 'a' &&
                ascii_lower((unsigned char)line[1]) == 'l' && ascii_lower((unsigned char)line[2]) == 'l' &&
                ascii_lower((unsigned char)line[3]) == 'o' && ascii_lower((unsigned char)line[4]) == 'w') ||
                ascii_span_contains_ci(line, length, "decision=\"allow\"") ||
                ascii_span_contains_ci(line, length, "decision = \"allow\"") ||
                ascii_span_contains_ci(line, length, "decision='allow'") ||
                ascii_span_contains_ci(line, length, "decision = 'allow'")) {
                target->allow_rule_count++;
            } else if ((length >= 4 && ascii_lower((unsigned char)line[0]) == 'd' &&
                ascii_lower((unsigned char)line[1]) == 'e' && ascii_lower((unsigned char)line[2]) == 'n' &&
                ascii_lower((unsigned char)line[3]) == 'y') ||
                ascii_span_contains_ci(line, length, "decision=\"deny\"") ||
                ascii_span_contains_ci(line, length, "decision = \"deny\"") ||
                ascii_span_contains_ci(line, length, "decision='deny'") ||
                ascii_span_contains_ci(line, length, "decision = 'deny'")) {
                target->deny_rule_count++;
            }
        }
        if (!end) break;
        cursor = end + 1;
    }
}

static void inspect_known_artifact(bl_operator_target_t *target) {
    const long long max_bytes = 8LL * 1024LL * 1024LL;
    HANDLE file;
    char *text;
    DWORD length;
    DWORD read_count = 0;
    static const char *credential_keys[] = {
        "access_token", "accessToken", "refresh_token", "refreshToken",
        "api_key", "apiKey", "apikey", "token", "credential", "oauth", "claudeAiOauth"
    };
    static const char *token_keys[] = {
        "access_token", "accessToken", "refresh_token", "refreshToken",
        "api_key", "apiKey", "apikey", "token", "oauth"
    };
    static const char *refresh_keys[] = {
        "refresh_token", "refreshToken", "refresh", "refresh_expires", "refreshExpires"
    };
    static const char *account_keys[] = {
        "email", "account_id", "accountId", "account", "tenant_id", "tenantId",
        "workspace_id", "workspaceId", "user_id", "userId"
    };
    static const char *expiration_keys[] = {
        "expires", "expires_at", "expiresAt", "expiration", "expiry", "valid_until", "validUntil"
    };
    static const char *auth_state_keys[] = {
        "auth_state", "authState", "authenticated", "logged_in", "loggedIn", "login_state", "loginState", "status"
    };
    static const char *config_keys[] = {
        "permissions", "hooks", "env", "statusLine", "enabledPlugins", "extraKnownMarketplaces",
        "mcpServers", "theme", "autoUpdates", "installMethod", "hasCompletedOnboarding",
        "alwaysThinkingEnabled", "includeCoAuthoredBy", "cleanupPeriodDays", "outputStyle",
        "apiKeyHelper", "language", "teammateMode", "attribution", "feedbackSurveyRate",
        "projects", "githubRepoPaths", "trust_level"
    };
    static const char *permission_keys[] = {
        "read_roots", "write_roots", "proxy_ports", "allow_local_binding",
        "sandbox_mode", "approval_policy", "permissions"
    };
    if (!target || !target_is_file(target)) return;
    if (family_is_session(target->family)) return;
    if (!path_has_inspectable_extension(target->path)) return;
    if (target->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        append_safe_signal(target, "inspection", "skipped_reparse");
        return;
    }
    if (g_inspection_files >= BL_INSPECTED_FILE_LIMIT || g_inspection_bytes >= BL_TOTAL_INSPECTION_BYTE_LIMIT) {
        target->analysis_truncated = 1;
        g_inspection_budget_exhausted = 1;
        append_safe_signal(target, "inspection", "budget_exhausted");
        return;
    }
    length = (DWORD)(target->size_bytes > max_bytes ? max_bytes : target->size_bytes);
    if ((long long)length > BL_TOTAL_INSPECTION_BYTE_LIMIT - g_inspection_bytes) {
        length = (DWORD)(BL_TOTAL_INSPECTION_BYTE_LIMIT - g_inspection_bytes);
        g_inspection_budget_exhausted = 1;
        append_safe_signal(target, "inspection", "budget_exhausted");
    }
    if (target->size_bytes > length) target->analysis_truncated = 1;
    g_inspection_files++;
    file = CreateFileW(target->path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        append_safe_signal(target, "inspection", "unavailable");
        return;
    }
    text = (char *)malloc((size_t)length + 1);
    if (!text) { CloseHandle(file); append_safe_signal(target, "inspection", "unavailable"); return; }
    if (length > 0 && !ReadFile(file, text, length, &read_count, NULL)) {
        CloseHandle(file);
        free(text);
        append_safe_signal(target, "inspection", "unavailable");
        return;
    }
    CloseHandle(file);
    g_inspection_bytes += read_count;
    text[read_count] = '\0';
    if (family_is_auth(target->family)) {
        target->credential_key_type_count = count_known_key_types(text, credential_keys, (int)(sizeof(credential_keys) / sizeof(credential_keys[0])));
        target->token_like_field_count = count_known_key_types(text, token_keys, (int)(sizeof(token_keys) / sizeof(token_keys[0])));
        target->refresh_field_count = count_known_key_types(text, refresh_keys, (int)(sizeof(refresh_keys) / sizeof(refresh_keys[0])));
        target->account_metadata_field_count = count_known_key_types(text, account_keys, (int)(sizeof(account_keys) / sizeof(account_keys[0])));
        target->expiration_field_count = count_known_key_types(text, expiration_keys, (int)(sizeof(expiration_keys) / sizeof(expiration_keys[0])));
        target->auth_state_field_count = count_known_key_types(text, auth_state_keys, (int)(sizeof(auth_state_keys) / sizeof(auth_state_keys[0])));
    }
    if (family_is_config(target->family)) {
        count_assignment_signal(target, text, "model_provider");
        count_assignment_signal(target, text, "sandbox_mode");
        count_assignment_signal(target, text, "sandbox");
        count_assignment_signal(target, text, "approval_policy");
        count_assignment_signal(target, text, "model_reasoning_effort");
        count_assignment_signal(target, text, "model");
        extract_mcp_signals(target, text);
        extract_project_trust_signals(target, text);
        target->config_setting_count += count_known_key_types(text, config_keys, (int)(sizeof(config_keys) / sizeof(config_keys[0])));
        if (target->config_setting_count > 0) {
            char count_text[24];
            snprintf(count_text, sizeof(count_text), "%d", target->config_setting_count);
            append_safe_signal(target, "recognized_settings", count_text);
        }
        if (target_family_is(target, "rules")) count_rule_metadata(target, text);
        if (target_family_is(target, "sandbox") || target_family_is(target, "permissions")) {
            char count_text[24];
            target->permission_setting_count = count_known_key_types(text, permission_keys, (int)(sizeof(permission_keys) / sizeof(permission_keys[0])));
            if (target->permission_setting_count > 0) {
                snprintf(count_text, sizeof(count_text), "%d", target->permission_setting_count);
                append_safe_signal(target, "permission_settings", count_text);
            }
        }
    }
    free(text);
}

static int target_is_tier2_review(const bl_operator_target_t *target) {
    return target && target->priority_tier == 2;
}

static int target_is_session_context(const bl_operator_target_t *target) {
    return target && target->priority_tier == 3;
}

static int target_inspection_unavailable(const bl_operator_target_t *target);

static int target_assessment_category(const bl_operator_target_t *target) {
    if (!target) return 0;
    if (family_is_auth(target->family)) return 3;
    if (target_family_is(target, "rules") || target_family_is(target, "permissions") ||
        target_family_is(target, "sandbox")) return 2;
    if (family_is_config(target->family)) return 1;
    return 0;
}

static int target_metadata_field_count(const bl_operator_target_t *target) {
    int count;
    const char *cursor = target ? target->safe_signals : NULL;
    if (!target) return 0;
    count = target->credential_key_type_count + target->config_setting_count + target->connector_definition_count +
        target->rule_count + target->permission_setting_count + target->token_like_field_count + target->refresh_field_count +
        target->account_metadata_field_count + target->expiration_field_count + target->auth_state_field_count;
    if (count > 0) return count;
    while (cursor && *cursor) {
        const char *end = strstr(cursor, ", ");
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (!(length >= 11 && strncmp(cursor, "inspection=", 11) == 0)) count++;
        if (!end) break;
        cursor = end + 2;
    }
    return count;
}

static int target_metadata_parsed(const bl_operator_target_t *target) {
    return target && target_is_file(target) && path_has_inspectable_extension(target->path) &&
        !target_inspection_unavailable(target);
}

static int compact_category(const bl_operator_target_t *target) {
    if (!target) return 0;
    if (target_is_file(target) && (target_family_is(target, "config") || target_family_is(target, "mcp"))) return 1;
    if (target_is_file(target) && (target_family_is(target, "rules") || target_family_is(target, "permissions") ||
        target_family_is(target, "sandbox"))) return 2;
    if (target_is_file(target) && target_family_is(target, "auth")) return 3;
    if (target_family_is(target, "sessions") || target_family_is(target, "history") ||
        (target_family_is(target, "workspace") &&
         (target_tool_is(target, "claude_code") || target_tool_is(target, "cursor")))) return 4;
    return 0;
}

static const char *tool_display_name(const char *tool) {
    if (strcmp(tool, "codex") == 0) return "CODEX";
    if (strcmp(tool, "claude_code") == 0) return "CLAUDE CODE";
    if (strcmp(tool, "cursor") == 0) return "CURSOR";
    if (strcmp(tool, "antigravity_cli") == 0) return "ANTIGRAVITY CLI";
    if (strcmp(tool, "grok") == 0) return "GROK";
    return tool;
}

static void print_count_label(int count, const char *singular, const char *plural) {
    printf("%d %s", count, count == 1 ? singular : plural);
}

static void print_config_annotations(const bl_operator_target_t *target) {
    const char *cursor;
    int printed = 0;
    if (!target || !target->safe_signals[0]) return;
    cursor = target->safe_signals;
    while (cursor && *cursor) {
        const char *comma = strstr(cursor, ", ");
        char signal[96];
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        if (length >= sizeof(signal)) length = sizeof(signal) - 1;
        memcpy(signal, cursor, length);
        signal[length] = '\0';
        if (strncmp(signal, "inspection=", 11) != 0 &&
            strncmp(signal, "recognized_settings=", 20) != 0) {
            printf("%s%s", printed ? " | " : " | ", signal);
            printed++;
        }
        if (!comma) break;
        cursor = comma + 2;
    }
}

static void print_compact_health(const char *tool, int category) {
    int i;
    int partial = 0;
    int unreadable = 0;
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (strcmp(target->tool, tool) != 0 || compact_category(target) != category) continue;
        partial += target->analysis_truncated ? 1 : 0;
        unreadable += target_inspection_unavailable(target) ? 1 : 0;
    }
    if (partial) printf(", %d partial", partial);
    if (unreadable) printf(", %d unreadable", unreadable);
}

static int target_signal_count(const bl_operator_target_t *target, const char *prefix) {
    const char *match;
    if (!target || !prefix) return 0;
    match = strstr(target->safe_signals, prefix);
    return match ? atoi(match + strlen(prefix)) : 0;
}

static void print_assessment_summary(void) {
    static const char *tools[] = {"codex", "claude_code", "cursor", "antigravity_cli", "grok"};
    int i;
    int tool_count = 0, auth_count = 0, trusted = 0, sessions = 0, session_artifacts = 0;
    int partial = g_operator_target_overflow || g_dynamic_scan_partial || g_session_scan_partial;
    int refresh_seen[BL_SESSION_TOOL_COUNT] = {0};
    int recent_seen[BL_SESSION_TOOL_COUNT] = {0};
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        int tool_index;
        trusted += target_signal_count(target, "trusted=");
        if (compact_category(target) == 3) auth_count++;
        if (compact_category(target) == 4) sessions++;
        for (tool_index = 0; tool_index < BL_SESSION_TOOL_COUNT; tool_index++) {
            if (strcmp(target->tool, tools[tool_index]) != 0) continue;
            if (target->refresh_field_count > 0) refresh_seen[tool_index] = 1;
            if (compact_category(target) == 4 && target->last_write_time.dwLowDateTime) recent_seen[tool_index] = 1;
            break;
        }
    }
    for (i = 0; i < BL_SESSION_TOOL_COUNT; i++) {
        int j;
        for (j = 0; j < g_operator_target_count; j++) if (strcmp(g_operator_targets[j].tool, tools[i]) == 0) { tool_count++; break; }
    }
    for (i = 0; i < BL_SESSION_TOOL_COUNT; i++) session_artifacts += g_session_artifact_counts[i];
    printf("[i] ASSESSMENT SUMMARY\n[i]   Tools detected:       %d\n", tool_count);
    if (auth_count) { printf("[+]   Credential stores:    "); print_count_label(auth_count, "file", "files"); printf("\n"); }
    for (i = 0; i < BL_SESSION_TOOL_COUNT; i++) if (refresh_seen[i]) { int first = 1, j; printf("[+]   Refresh material:     "); for (j = 0; j < BL_SESSION_TOOL_COUNT; j++) if (refresh_seen[j]) { printf("%s%s", first ? "" : ", ", tool_display_name(tools[j])); first = 0; } printf("\n"); break; }
    if (trusted) printf("[+]   Trusted projects:     %d\n", trusted);
    if (sessions) printf("[i]   Session locations:    %d\n", sessions);
    if (sessions || g_session_scan_partial) printf("[i]   Session artifacts:    %d%s\n", session_artifacts, g_session_scan_partial ? " (partial scan)" : "");
    for (i = 0; i < BL_SESSION_TOOL_COUNT; i++) if (recent_seen[i]) { int first = 1, j; printf("[i]   Recent activity:      "); for (j = 0; j < BL_SESSION_TOOL_COUNT; j++) if (recent_seen[j]) { printf("%s%s", first ? "" : ", ", tool_display_name(tools[j])); first = 0; } printf("\n"); break; }
    printf("%s   Discovery status:     %s\n[i]\n", partial ? "[!]" : "[i]", partial ? "PARTIAL" : "COMPLETE");
}

static void print_tool_assessment(const char *tool) {
    int i;
    int present = 0;
    int counts[5] = {0, 0, 0, 0, 0};
    int config_settings = 0;
    int allow_rules = 0;
    int deny_rules = 0;
    int token_fields = 0;
    int refresh_fields = 0;
    FILETIME latest = {0, 0};
    int tool_slot = session_tool_slot(tool);
    int session_artifacts = tool_slot >= 0 ? g_session_artifact_counts[tool_slot] : 0;
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        int category;
        if (strcmp(target->tool, tool) != 0) continue;
        present = 1;
        category = compact_category(target);
        if (category > 0) counts[category]++;
        if (category == 1) config_settings += target->config_setting_count;
        if (category == 2) {
            allow_rules += target->allow_rule_count;
            deny_rules += target->deny_rule_count;
        }
        if (category == 3) {
            token_fields += target->token_like_field_count;
            refresh_fields += target->refresh_field_count;
        }
        if (category == 4 && CompareFileTime(&target->last_write_time, &latest) > 0) latest = target->last_write_time;
    }
    if (!present) return;

    printf("[i] %s\n", tool_display_name(tool));
    if (counts[3]) { printf("[+]   "); print_count_label(counts[3], "credential file", "credential files"); printf(" | "); print_count_label(token_fields, "suspected credential field", "suspected credential fields"); if (refresh_fields) printf(" | refresh token indicator present"); print_compact_health(tool, 3); printf("\n"); }
    if (counts[2]) { printf("[i]   "); print_count_label(counts[2], "rules file", "rules files"); printf(" | "); print_count_label(allow_rules, "allow rule", "allow rules"); printf("\n"); }
    if (counts[1]) { printf("[i]   "); print_count_label(counts[1], "config file", "config files"); printf(" | "); print_count_label(config_settings, "recognized setting", "recognized settings"); print_compact_health(tool, 1); printf("\n"); }
    if (session_artifacts && g_top_sessions[tool_slot * BL_TOP_SESSIONS_PER_TOOL].tool) latest = g_top_sessions[tool_slot * BL_TOP_SESSIONS_PER_TOOL].last_write_time;
    if (counts[4] || session_artifacts) { SYSTEMTIME utc; printf("[i]   "); print_count_label(counts[4], "session location", "session locations"); printf(" | "); print_count_label(session_artifacts, "session artifact", "session artifacts"); if (g_session_scan_partial) printf(" (partial scan)"); if (FileTimeToSystemTime(&latest, &utc)) printf(" | latest activity %04d-%02d-%02d", utc.wYear, utc.wMonth, utc.wDay); print_compact_health(tool, 4); printf("\n"); }
    printf("[i]\n");

    if (counts[3]) {
        printf("[+] AUTHENTICATION ARTIFACTS\n    ");
        print_count_label(token_fields, "suspected credential field", "suspected credential fields");
        if (refresh_fields) printf(" | refresh token indicator present");
        printf("\n");
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (strcmp(target->tool, tool) == 0 && compact_category(target) == 3) {
                printf("    "); bl_print_wide_utf8(target->path); printf("\n");
            }
        }
        printf("\n");
    }
    if (counts[2]) {
        printf("[i] RULES\n    %d allow rules | %d deny rules\n", allow_rules, deny_rules);
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (strcmp(target->tool, tool) == 0 && compact_category(target) == 2) {
                printf("    "); bl_print_wide_utf8(target->path); printf("\n");
            }
        }
        printf("\n");
    }
    if (counts[1]) {
        int printed = 0;
        printf("[i] CONFIGURATION\n");
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (strcmp(target->tool, tool) == 0 && compact_category(target) == 1) {
                if (printed) printf("\n");
                printf("    "); print_count_label(target->config_setting_count, "recognized setting", "recognized settings");
                print_config_annotations(target);
                printf("\n    ");
                bl_print_wide_utf8(target->path); printf("\n");
                printed++;
            }
        }
        printf("\n");
    }
    if (counts[4]) {
        printf("[i] SESSION LOCATIONS\n");
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (strcmp(target->tool, tool) == 0 && compact_category(target) == 4) {
                printf("    "); bl_print_wide_utf8(target->path); printf("\n");
            }
        }
        printf("\n");
    }
}

static void print_other_recognized_paths(void) {
    int i;
    int count = 0;
    for (i = 0; i < g_operator_target_count; i++) {
        int j;
        int seen = 0;
        if (compact_category(&g_operator_targets[i]) != 0) continue;
        for (j = 0; j < i; j++) {
            if (compact_category(&g_operator_targets[j]) == 0 &&
                _wcsicmp(g_operator_targets[i].path, g_operator_targets[j].path) == 0) {
                seen = 1;
                break;
            }
        }
        if (!seen) count++;
    }
    if (count) printf("[i] Additional candidate artifacts: %d\n", count);
}

static void print_assessment_category(int category, const char *title) {
    int i;
    int printed = 0;
    printf("[i] %d. %s\n", category, title);
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        int fields;
        if (target_assessment_category(target) != category) continue;
        fields = target_metadata_field_count(target);
        printf("[i]   %s %s\n", target->tool, target->family);
        printf("[i]     Parsed: %s%s\n", target_metadata_parsed(target) ? "yes" : "no",
            target->analysis_truncated ? " (partial)" : "");
        printf("[i]     Metadata fields: %d\n", fields);
        if (category == 1) {
            printf("[i]     Recognized settings: %d\n", target->config_setting_count);
            printf("[i]     Connector definitions: %d\n", target->connector_definition_count);
        } else if (category == 2) {
            printf("[i]     Rules: %d\n", target->rule_count);
            printf("[i]     Allow entries: %d\n", target->allow_rule_count);
            printf("[i]     Deny entries: %d\n", target->deny_rule_count);
            printf("[i]     Permission settings: %d\n", target->permission_setting_count);
        } else if (category == 3) {
            printf("[i]     Secret-like fields: %d\n", target->credential_key_type_count);
            printf("[i]     Token-like fields: %d\n", target->token_like_field_count);
            printf("[i]     Refresh-related fields: %d\n", target->refresh_field_count);
            printf("[i]     Account-metadata fields: %d\n", target->account_metadata_field_count);
            printf("[i]     Expiration fields: %d\n", target->expiration_field_count);
            printf("[i]     Authentication-state fields: %d\n", target->auth_state_field_count);
        }
        printf("[i]     Path: ");
        bl_print_wide_utf8(target->path);
        printf("\n");
        printed++;
    }
    if (!printed) printf("[i]   none\n");
    printf("[i]\n");
}

static int target_inspection_unavailable(const bl_operator_target_t *target) {
    return target && strstr(target->safe_signals, "inspection=unavailable") != NULL;
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

static void print_collection_first(void) {
    int i;
    int printed = 0;
    char size_text[32];
    long long total_size = 0;
    int total_count = 0;
    for (i = 0; i < g_operator_target_count; i++) {
        if (g_operator_targets[i].auto_select) {
            total_count++;
            total_size += g_operator_targets[i].size_bytes;
        }
    }
    format_size(total_size, size_text, sizeof(size_text));
    printf("[i] Collect now (%d artifact(s), %s)\n", total_count, size_text);
    for (i = 0; i < g_operator_target_count; i++) {
        const bl_operator_target_t *target = &g_operator_targets[i];
        if (!target->auto_select) {
            continue;
        }
        format_size(target->size_bytes, size_text, sizeof(size_text));
        printf(
            "[i]   [%d] %s %s - %s",
            target->priority_tier,
            target->tool,
            target->family,
            size_text
        );
        if (target->credential_key_type_count > 0) {
            printf(", credential key types=%d", target->credential_key_type_count);
        }
        if (target_inspection_unavailable(target)) printf(", inspection unavailable");
        else if (target->analysis_truncated) printf(", partial");
        printf("\n[i]       "); bl_print_wide_utf8(target->path); printf("\n");
        printed++;
    }
    if (!printed) {
        printf("[i]   none\n");
    }
    {
        int containers = 0;
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (target->priority_tier != 1 || target->auto_select) continue;
            if (!containers) printf("[i] Auth containers requiring review\n");
            printf("[i]   [1] %s %s - auth_container_review\n[i]       ", target->tool, target->family);
            bl_print_wide_utf8(target->path); printf("\n");
            containers++;
        }
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
        has_config |= family_is_config(target->family) && !target_family_is(target, "rules") &&
            !target_family_is(target, "sandbox") && !target_family_is(target, "plugins") &&
            !target_family_is(target, "extensions") && !target_family_is(target, "skills");
        has_rules |= target_family_is(target, "rules");
        has_sandbox |= target_family_is(target, "sandbox") || wcsstr(target->path, L"\\.sandbox-secrets\\") != NULL;
        has_plugins |= target_family_is(target, "plugins") || target_family_is(target, "extensions") || target_family_is(target, "skills");
        has_other |= !(family_is_config(target->family) || target_family_is(target, "rules") ||
            target_family_is(target, "sandbox") || target_family_is(target, "plugins") ||
            target_family_is(target, "extensions") || target_family_is(target, "skills") ||
            wcsstr(target->path, L"\\.sandbox-secrets\\") != NULL);
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
            printf("[i]       "); bl_print_wide_utf8(target->path);
            if (target->safe_signals[0] && strcmp(target->safe_signals, "inspection=unavailable") != 0) {
                printf(" (%s", target->safe_signals);
                if (target->analysis_truncated) printf(", partial");
                printf(")");
            } else if (target->analysis_truncated) printf(" (partial)");
            else if (target_inspection_unavailable(target)) printf(" (inspection unavailable)");
            printf("\n");
        }
    }
}

static void print_review_next(void) {
    int i;
    int printed = 0;
    printf("[i] Capabilities and security configuration\n");
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
            printed++;
        }
    }
    if (!printed) printf("[i]   none\n");
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
        long long records;
        long long malformed;
        int partial;
        int unavailable;
        FILETIME latest;
        int printed;
    } session_group_t;
    session_group_t groups[32];
    printf("[i] 4. Session candidates\n");
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
            groups[index].records = 0;
            groups[index].malformed = 0;
            groups[index].partial = 0;
            groups[index].unavailable = 0;
            groups[index].latest.dwLowDateTime = 0;
            groups[index].latest.dwHighDateTime = 0;
            groups[index].printed = 0;
        }
        groups[index].count++;
        groups[index].records += target->record_count;
        groups[index].malformed += target->malformed_record_count;
        groups[index].partial += target->analysis_truncated;
        groups[index].unavailable += target_inspection_unavailable(target);
        if (CompareFileTime(&target->last_write_time, &groups[index].latest) > 0) {
            groups[index].latest = target->last_write_time;
        }
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
        printf("[i]   [3] %s history/session artifacts x%d", groups[best].tool, groups[best].count);
        if (groups[best].latest.dwLowDateTime || groups[best].latest.dwHighDateTime) {
            SYSTEMTIME utc;
            if (FileTimeToSystemTime(&groups[best].latest, &utc)) {
                printf(", latest=%04d-%02d-%02d", utc.wYear, utc.wMonth, utc.wDay);
            }
        }
        if (groups[best].partial > 0) printf(", partial=%d", groups[best].partial);
        if (groups[best].unavailable > 0) printf(", unreadable=%d", groups[best].unavailable);
        printf("\n");
        for (i = 0; i < g_operator_target_count; i++) {
            const bl_operator_target_t *target = &g_operator_targets[i];
            if (!target_is_session_context(target) || strcmp(target->tool, groups[best].tool) != 0) {
                continue;
            }
            printf("[i]       ");
            bl_print_wide_utf8(target->path);
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
            for (j = 0; j < g_operator_target_count; j++) {
                const bl_operator_target_t *target = &g_operator_targets[j];
                if (target->priority_tier == tier && strcmp(target->family, family) == 0) {
                    printf("[i]       ");
                    bl_print_wide_utf8(target->path);
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

static void print_session_files(const char *heading, const bl_session_candidate_t *sessions, int session_count) {
    int i;
    int rank = 0;
    printf("[i] %s%s\n", heading, g_session_scan_partial ? " (partial scan)" : "");
    if (session_count == 0) printf("[i]   none\n");
    for (i = 0; i < BL_TOP_SESSION_COUNT; i++) {
        const bl_session_candidate_t *target = &sessions[i];
        char size_text[32];
        wchar_t project[BL_MAX_PATH_LEN] = {0};
        const wchar_t *project_start;
        SYSTEMTIME utc;
        if (!target->tool) continue;
        format_size(target->size_bytes, size_text, sizeof(size_text));
        rank = (i % BL_TOP_SESSIONS_PER_TOOL) + 1;
        project_start = wcsstr(target->path, L"\\projects\\");
        if (project_start && (strcmp(target->tool, "claude_code") == 0 || strcmp(target->tool, "cursor") == 0)) {
            size_t length = 0;
            size_t last_dash = 0;
            project_start += 10;
            while (project_start[length] && project_start[length] != L'\\' && length + 1 < BL_MAX_PATH_LEN) { project[length] = project_start[length]; if (project[length] == L'-') last_dash = length; length++; }
            project[length] = L'\0';
            if (last_dash && project[last_dash + 1]) memmove(project, project + last_dash + 1, (wcslen(project + last_dash + 1) + 1) * sizeof(wchar_t));
        }
        printf("[+] [%d] %s | %s", rank, tool_display_name(target->tool), size_text);
        if (FileTimeToSystemTime(&target->last_write_time, &utc)) printf(" | modified %04d-%02d-%02d", utc.wYear, utc.wMonth, utc.wDay);
        if (project[0]) { printf(" | project="); bl_print_wide_utf8(project); }
        printf("\n        ");
        bl_print_wide_utf8(target->path);
        printf("\n");
    }
    printf("[i]\n");
}

static void print_operator_triage_summary(void) {
    static const char *tools[] = {"codex", "claude_code", "cursor", "antigravity_cli", "grok"};
    int i;
    printf("[i] Blacklight endpoint assessment\n[i]\n");
    if (g_operator_target_count <= 0) {
        printf("[i]   0 artifacts found\n");
        return;
    }
    qsort(
        g_operator_targets,
        (size_t)g_operator_target_count,
        sizeof(g_operator_targets[0]),
        operator_target_compare
    );
    print_assessment_summary();
    for (i = 0; i < (int)(sizeof(tools) / sizeof(tools[0])); i++) print_tool_assessment(tools[i]);
    print_session_files("PRIORITIZED SESSION ARTIFACTS (newest first)", g_top_sessions, g_top_session_count);
    print_session_files("LARGEST SESSION ARTIFACTS", g_largest_sessions, g_largest_session_count);
    print_other_recognized_paths();
    if (g_operator_target_overflow) printf("[!] Result storage cap reached at %d artifacts. Results are incomplete.\n", BL_MAX_OPERATOR_TARGETS);
}

static void windows_emit_triage(const char *tool, const char *family, const char *type, const void *path) {
    const wchar_t *wide_path = (const wchar_t *)path;
    WIN32_FILE_ATTRIBUTE_DATA data = {0};
    long long size_bytes = 0;
    long long child_count = 0;
    int child_count_partial = 0;
    int child_count_unavailable = 0;
    int metadata_available;
    int priority_tier;
    const char *parser_hint;
    int sandbox_secret_path;
    int auth_adjacent_config_path;
    bl_operator_target_t *recorded;
    metadata_available = GetFileAttributesExW(wide_path, GetFileExInfoStandard, &data) != 0;
    if (metadata_available) {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                child_count_unavailable = 1;
            } else if (g_triage_max_depth > 0) {
                child_count = count_directory_children(wide_path, g_triage_max_depth, &child_count_partial, &child_count_unavailable);
            }
        } else {
            size_bytes = ((long long)data.nFileSizeHigh << 32) | data.nFileSizeLow;
        }
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
    parser_hint = bl_triage_parser_hint(family, path_is_sqlite(wide_path));
    recorded = record_operator_target(
        tool,
        family,
        type,
        wide_path,
        priority_tier,
        parser_hint,
        size_bytes,
        child_count,
        priority_tier == 1 && strcmp(type, "file") == 0,
        child_count_partial,
        child_count_unavailable,
        metadata_available ? data.dwFileAttributes : INVALID_FILE_ATTRIBUTES
    );
    if (recorded) {
        if (!metadata_available) append_safe_signal(recorded, "metadata", "unavailable");
        else {
        recorded->last_write_time = data.ftLastWriteTime;
        inspect_known_artifact(recorded);
        }
    }
    if (priority_tier == 1 && strcmp(type, "file") == 0) {
        g_auto_select_count++;
    }
}

static int windows_expand_path(const void *pattern, void *expanded, size_t expanded_size) {
    DWORD needed = ExpandEnvironmentStringsW((const wchar_t *)pattern, (wchar_t *)expanded, (DWORD)expanded_size);
    if (needed > 0 && needed <= expanded_size) {
        wchar_t *cursor = (wchar_t *)expanded;
        while (*cursor) {
            if (*cursor == L'/') *cursor = L'\\';
            cursor++;
        }
        return 1;
    }
    return 0;
}

static int windows_report_path_if_exists(
    const char *tool,
    const char *family,
    const void *path,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters,
    bl_emit_fn emit
) {
    DWORD attributes;
    const char *type;
    if (!bl_target_allowed(tool, filters)) {
        results->filtered_count++;
        return 0;
    }
    attributes = GetFileAttributesW((const wchar_t *)path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    type = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? "directory" : "file";
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        results->directory_count++;
    } else {
        results->file_count++;
    }
    results->hit_count++;
    emit(tool, family, type, path);
    return 1;
}

static int operator_path_recorded(const wchar_t *path) {
    int i;
    for (i = 0; i < g_operator_target_count; i++) {
        if (_wcsicmp(g_operator_targets[i].path, path) == 0) return 1;
    }
    return 0;
}

static void report_dynamic_file(
    const char *tool,
    const char *family,
    const wchar_t *path,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters
) {
    if (operator_path_recorded(path)) return;
    windows_report_path_if_exists(tool, family, path, results, filters, windows_emit_triage);
}

static void scan_dynamic_tree(
    const char *tool,
    const wchar_t *directory,
    int depth,
    int include_plan_metadata,
    bl_scan_results_t *results,
    const bl_scan_filters_t *filters
) {
    wchar_t search[BL_MAX_PATH_LEN];
    wchar_t child[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW data;
    HANDLE handle;
    size_t length;
    if (depth < 0 || g_dynamic_entries_scanned >= g_dynamic_discovery_limit ||
        g_dynamic_root_entries_scanned >= g_dynamic_root_limit) {
        if (g_dynamic_entries_scanned >= g_dynamic_discovery_limit ||
            g_dynamic_root_entries_scanned >= g_dynamic_root_limit) g_dynamic_scan_partial = 1;
        return;
    }
    length = wcslen(directory);
    if (length + 3 >= BL_MAX_PATH_LEN) return;
    wcscpy(search, directory);
    if (length && search[length - 1] != L'\\') search[length++] = L'\\';
    search[length++] = L'*';
    search[length] = L'\0';
    handle = FindFirstFileW(search, &data);
    if (handle == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        if (g_dynamic_entries_scanned >= g_dynamic_discovery_limit ||
            g_dynamic_root_entries_scanned >= g_dynamic_root_limit) { g_dynamic_scan_partial = 1; break; }
        g_dynamic_entries_scanned++;
        g_dynamic_root_entries_scanned++;
        if (length + wcslen(data.cFileName) + 1 >= BL_MAX_PATH_LEN) continue;
        wcscpy(child, directory);
        if (length && child[wcslen(child) - 1] != L'\\') wcscat(child, L"\\");
        wcscat(child, data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (depth > 0) scan_dynamic_tree(tool, child, depth - 1, include_plan_metadata, results, filters);
        } else if (_wcsicmp(data.cFileName, L".mcp.json") == 0) {
            report_dynamic_file(tool, "mcp", child, results, filters);
        } else if (strcmp(tool, "claude_code") == 0 && _wcsicmp(data.cFileName, L"sessions-index.json") == 0) {
            report_dynamic_file(tool, "sessions", child, results, filters);
        } else if (include_plan_metadata) {
            size_t name_length = wcslen(data.cFileName);
            if (name_length >= 8 && _wcsicmp(data.cFileName + name_length - 8, L".plan.md") == 0)
                report_dynamic_file(tool, "plans", child, results, filters);
        }
    } while (FindNextFileW(handle, &data));
    FindClose(handle);
}

static void scan_dynamic_targets(bl_scan_results_t *results, const bl_scan_filters_t *filters) {
    wchar_t profile[BL_MAX_PATH_LEN];
    wchar_t root[BL_MAX_PATH_LEN];
    wchar_t pattern[BL_MAX_PATH_LEN];
    wchar_t path[BL_MAX_PATH_LEN];
    WIN32_FIND_DATAW data;
    HANDLE handle;
    DWORD needed = ExpandEnvironmentStringsW(L"%USERPROFILE%", profile, BL_MAX_PATH_LEN);
    int allowed_roots = 0;
    if (needed == 0 || needed > BL_MAX_PATH_LEN) return;
    allowed_roots += bl_target_allowed("codex", filters) ? 1 : 0;
    allowed_roots += bl_target_allowed("claude_code", filters) ? 1 : 0;
    allowed_roots += bl_target_allowed("cursor", filters) ? 2 : 0;
    if (allowed_roots == 0) return;
    g_dynamic_root_limit = g_dynamic_discovery_limit / allowed_roots;

    if (bl_target_allowed("codex", filters)) {
        g_dynamic_root_entries_scanned = 0;
        _snwprintf(root, BL_MAX_PATH_LEN - 1, L"%ls\\.codex\\rules", profile);
        _snwprintf(pattern, BL_MAX_PATH_LEN - 1, L"%ls\\*.rules", root);
        handle = FindFirstFileW(pattern, &data);
        if (handle != INVALID_HANDLE_VALUE) {
            do {
                if (g_dynamic_entries_scanned >= g_dynamic_discovery_limit ||
                    g_dynamic_root_entries_scanned >= g_dynamic_root_limit) { g_dynamic_scan_partial = 1; break; }
                g_dynamic_entries_scanned++;
                g_dynamic_root_entries_scanned++;
                if ((data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) continue;
                _snwprintf(path, BL_MAX_PATH_LEN - 1, L"%ls\\%ls", root, data.cFileName);
                report_dynamic_file("codex", "rules", path, results, filters);
            } while (FindNextFileW(handle, &data));
            FindClose(handle);
        }
    }

    if (bl_target_allowed("claude_code", filters)) {
        g_dynamic_root_entries_scanned = 0;
        _snwprintf(root, BL_MAX_PATH_LEN - 1, L"%ls\\.claude\\projects", profile);
        scan_dynamic_tree("claude_code", root, BL_DYNAMIC_DISCOVERY_MAX_DEPTH, 0, results, filters);
    }
    if (bl_target_allowed("cursor", filters)) {
        g_dynamic_root_entries_scanned = 0;
        _snwprintf(root, BL_MAX_PATH_LEN - 1, L"%ls\\.cursor\\projects", profile);
        scan_dynamic_tree("cursor", root, BL_DYNAMIC_DISCOVERY_MAX_DEPTH, 0, results, filters);
        g_dynamic_root_entries_scanned = 0;
        _snwprintf(root, BL_MAX_PATH_LEN - 1, L"%ls\\.cursor\\plans", profile);
        scan_dynamic_tree("cursor", root, 0, 1, results, filters);
    }
}

static int append_csv_value(char *dst, size_t dst_size, const char *value) {
    size_t used = strlen(dst);
    size_t value_len = strlen(value);
    if (used != 0) {
        if (used + 1 >= dst_size) {
            return 0;
        }
        dst[used++] = ',';
        dst[used] = '\0';
    }
    if (used + value_len >= dst_size) {
        return 0;
    }
    memcpy(dst + used, value, value_len + 1);
    return 1;
}

static void print_usage(FILE *stream, const char *program) {
    fprintf(stream, "Blacklight Scout Windows executable %s\n", BL_SCOUT_VERSION);
    fprintf(stream, "usage: %s [--out PATH] [filters]\n", program);
    fprintf(stream, "  no arguments       run bounded human triage immediately\n");
    fprintf(stream, "  --out PATH         write output to a file\n");
    fprintf(stream, "  --max-depth N      directory child-count depth (default: 1, maximum: %d)\n", BL_MAX_CHILD_COUNT_DEPTH);
    fprintf(stream, "  --discovery-cap N  dynamic-discovery entry cap (default: %d)\n", BL_DYNAMIC_DISCOVERY_LIMIT);
    fprintf(stream, "  --include-tool TOOL | --exclude-tool TOOL\n");
    fprintf(stream, "  --version          print the executable version\n");
}

int main(int argc, char **argv) {
    bl_scan_filters_t filters = {0};
    bl_scan_results_t results = {0};
    char tools[BL_MAX_PATH_LEN] = {0};
    char exclude_tools[BL_MAX_PATH_LEN] = {0};
    const char *output_path = NULL;
    int i;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("ai_path_scout-windows-x64 %s\n", BL_SCOUT_VERSION);
            return 0;
        }
    }
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if ((strcmp(argv[i], "--include-tool") == 0 || strcmp(argv[i], "--tool") == 0) && i + 1 < argc) {
            if (!append_csv_value(tools, sizeof(tools), argv[++i])) {
                return 2;
            }
        } else if (strcmp(argv[i], "--exclude-tool") == 0 && i + 1 < argc) {
            if (!append_csv_value(exclude_tools, sizeof(exclude_tools), argv[++i])) {
                return 2;
            }
        } else if (strcmp(argv[i], "--max-depth") == 0 && i + 1 < argc) {
            char *end = NULL;
            long parsed;
            errno = 0;
            parsed = strtol(argv[++i], &end, 10);
            if (errno == ERANGE || !end || *end != '\0' || parsed < 0 || parsed > BL_MAX_CHILD_COUNT_DEPTH) {
                fprintf(stderr, "--max-depth must be between 0 and %d\n", BL_MAX_CHILD_COUNT_DEPTH);
                return 2;
            }
            g_triage_max_depth = (int)parsed;
        } else if (strcmp(argv[i], "--discovery-cap") == 0 && i + 1 < argc) {
            char *end = NULL;
            long parsed;
            errno = 0;
            parsed = strtol(argv[++i], &end, 10);
            if (errno == ERANGE || !end || *end != '\0' || parsed < 1 || parsed > 1000000) {
                fprintf(stderr, "--discovery-cap must be between 1 and 1000000\n");
                return 2;
            }
            g_dynamic_discovery_limit = (int)parsed;
        } else {
            print_usage(stderr, argv[0]);
            return 2;
        }
    }
    if (output_path) {
        g_output_file = bl_open_new_output_file(output_path);
        if (!g_output_file) {
            fprintf(stderr, "failed to create new output file: %s\n", output_path);
            return 2;
        }
    }
    filters.tools = tools;
    filters.tools_len = (int)strlen(tools);
    filters.exclude_tools = exclude_tools;
    filters.exclude_tools_len = (int)strlen(exclude_tools);
    filters.max_depth = g_triage_max_depth;
    filters.triage = 1;
    g_auto_select_count = 0;
    g_operator_target_count = 0;
    g_operator_target_overflow = 0;
    g_child_entries_scanned = 0;
    g_inspection_files = 0;
    g_inspection_bytes = 0;
    g_inspection_budget_exhausted = 0;
    g_dynamic_entries_scanned = 0;
    g_dynamic_scan_partial = 0;
    if (g_dynamic_discovery_limit < 1) g_dynamic_discovery_limit = BL_DYNAMIC_DISCOVERY_LIMIT;
    if (filters.tools_len > 0) {
        printf("[i] Include filters enabled\n");
    }
    if (filters.exclude_tools_len > 0) {
        printf("[i] Exclude filters enabled\n");
    }
    bl_scan_static_targets(
        BL_STATIC_TARGETS,
        BL_STATIC_TARGETS_COUNT,
        &results,
        &filters,
        windows_expand_path,
        windows_report_path_if_exists,
        windows_emit_triage
    );
    scan_dynamic_targets(&results, &filters);
    scan_session_candidates();
    print_operator_triage_summary();
    if (g_dynamic_scan_partial) {
        printf("[!] Discovery cap reached after %d candidate entries (per-root cap %d; run cap %d).\n", g_dynamic_entries_scanned, g_dynamic_root_limit, g_dynamic_discovery_limit);
        printf("[!] Results are incomplete. Increase --discovery-cap to continue.\n");
    }
    if (g_output_file) {
        fclose(g_output_file);
        g_output_file = NULL;
    }
    return 0;
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
    text_len = (int)wcslen(text);
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
