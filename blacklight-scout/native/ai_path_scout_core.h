/*
 * Blacklight Scout - shared AI path scout core
 *
 * Discovery-only path enumeration shared by Windows BOF, macOS dylib,
 * and Linux .so loaders. Does not read file contents.
 */

#ifndef BLACKLIGHT_AI_PATH_SCOUT_CORE_H
#define BLACKLIGHT_AI_PATH_SCOUT_CORE_H

#include <stddef.h>

#define BL_MAX_PATH_LEN 1024
#define BL_DISCOVERY_PROJECT_OUTPUTS 2
#define BL_DISCOVERY_CHAT_COMPANIONS 3
#define BL_DISCOVERY_WORKSPACE_DATABASES 4

typedef struct {
    const char *tool;
    const char *family;
#ifdef BLACKLIGHT_SCOUT_WINDOWS
    const wchar_t *pattern;
#else
    const char *pattern;
#endif
} bl_path_target_t;

typedef struct {
    int hit_count;
    int directory_count;
    int file_count;
    int filtered_count;
    int auto_select_count;
} bl_scan_results_t;

typedef struct {
    const char *tools;
    int tools_len;
    const char *exclude_tools;
    int exclude_tools_len;
    int max_depth;
    int triage;
} bl_scan_filters_t;

typedef void (*bl_emit_fn)(const char *tool, const char *family, const char *type, const void *path);

/* Relocatable env-root overlays. Static catalog stays home-relative; these are
 * checked at runtime when the named environment variables are set. */
#define BL_RELOC_DEVIN_SESSIONS_DIR (1u << 0)
#define BL_RELOC_DEVIN_SESSION_STORE_FILES (1u << 1)
#define BL_RELOC_KIRO_HOME (1u << 2)
#define BL_RELOC_KIRO_SESSIONS_DIR (1u << 3)

typedef struct {
    const char *family;
    const char *relative; /* empty string means the env root itself */
} bl_env_relative_target_t;

extern const bl_env_relative_target_t BL_DEVIN_SESSIONS_DIR_TARGETS[];
extern const size_t BL_DEVIN_SESSIONS_DIR_TARGETS_COUNT;
extern const bl_env_relative_target_t BL_KIRO_HOME_TARGETS[];
extern const size_t BL_KIRO_HOME_TARGETS_COUNT;
extern const bl_env_relative_target_t BL_KIRO_SESSIONS_DIR_TARGETS[];
extern const size_t BL_KIRO_SESSIONS_DIR_TARGETS_COUNT;
/* Home-relative Devin session roots to treat as sessions when
 * DEVIN_SESSION_STORE=files and DEVIN_SESSIONS_DIR is unset. */
extern const char *const BL_DEVIN_DEFAULT_SESSION_ROOTS[];
extern const size_t BL_DEVIN_DEFAULT_SESSION_ROOTS_COUNT;

int bl_target_allowed(const char *tool, const bl_scan_filters_t *filters);
int bl_loader_filter_tool(const char *value, int value_len, const char **canonical);
const char *bl_parser_hint_for_family(const char *family);
const char *bl_triage_parser_hint(const char *family, int sqlite_path);
int bl_triage_priority_tier(const char *family, int secret_like_path);
/* Format set relocatable env names (not values) into buffer. Returns 1 if any. */
int bl_relocatable_env_summary(unsigned int flags, char *buffer, size_t buffer_size);
int bl_ascii_equals_ci(const char *left, const char *right);
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
);

char *bl_scout_run(int argc, char **argv);

#endif
