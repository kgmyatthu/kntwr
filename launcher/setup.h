/*
 * setup.h - game folder discovery and persistence for the native KNTWR launcher.
 *
 * Order used by kntwr_setup_locate: saved config.json (beside the executable) -> every Steam library (registry + libraryfolders.vdf +
 * appmanifest_34030.acf) -> native folder picker (interactive only).  A candidate is accepted only when it contains Napoleon.exe.
 * Nothing is written except by kntwr_setup_save.  All functions return FALSE on failure or cancellation and never truncate output.
 */
#ifndef KNTWR_SETUP_H
#define KNTWR_SETUP_H

#include <windows.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Full path of config.json in the directory of the running executable ({"game_dir": "<UTF-8 JSON string>"}).
   FALSE if the path cannot be resolved or does not fit in `capacity` wide characters (including the terminator). */
BOOL kntwr_setup_config_path(wchar_t *out, size_t capacity);

/* Locates the game folder (the directory that contains Napoleon.exe), normalized to an absolute path without a trailing backslash.
   interactive == FALSE never shows UI.  interactive == TRUE falls back to the native folder picker (a pasted path is accepted;
   an invalid selection shows an error and lets the user retry or cancel).  Does not save.  FALSE: not found, cancelled, or `out`
   too small. */
BOOL kntwr_setup_locate(wchar_t *out, size_t capacity, BOOL interactive);

/* Explicit setup: always opens the native folder picker (no saved config, no Steam discovery).  The result contains Napoleon.exe
   and is normalized.  FALSE on cancel or failure.  Persists nothing. */
BOOL kntwr_setup_pick(wchar_t *out, size_t capacity);

/* Validates that `dir` (a folder, or the path of Napoleon.exe inside it) contains Napoleon.exe and persists the normalized folder
   to config.json atomically (temp file + replace).  FALSE: invalid directory or the file could not be written. */
BOOL kntwr_setup_save(const wchar_t *dir);

#ifdef __cplusplus
}
#endif

#endif
