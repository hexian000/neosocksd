/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_SLOG_H
#define UTILS_SLOG_H

#include <stdio.h>

enum {
	LOG_LEVEL_SILENCE,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_NOTICE,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_VERBOSE,
};
extern int slog_level;

enum {
	SLOG_OUTPUT_DISCARD,
	SLOG_OUTPUT_FILE,
	SLOG_OUTPUT_SYSLOG,
};
void slog_setoutput(int type, ...);

void slog_write(int level, const char *path, int line, const char *format, ...);

/* LOG: Log a message unconditionally. */
#define LOG_F(level, format, ...)                                              \
	slog_write(                                                            \
		(LOG_LEVEL_##level), __FILE__, __LINE__, (format),             \
		__VA_ARGS__);
#define LOG(level, message) LOG_F(LOG_LEVEL_##level, "%s", message)

#define LOGLEVEL(level) ((LOG_LEVEL_##level) <= slog_level)

/* Fatal: Serious problems that are likely to cause the program to exit. */
#define LOGF_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(FATAL)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(FATAL, format, __VA_ARGS__);                             \
	} while (0)
#define LOGF(message) LOGF_F("%s", message)

/* Error: Issues that shouldn't be ignored. */
#define LOGE_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(ERROR)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(ERROR, format, __VA_ARGS__);                             \
	} while (0)
#define LOGE(message) LOGE_F("%s", message)

/* Warning: Issues that may be ignored. */
#define LOGW_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(WARNING)) {                                      \
			break;                                                 \
		}                                                              \
		LOG_F(WARNING, format, __VA_ARGS__);                           \
	} while (0)
#define LOGW(message) LOGW_F("%s", message)

/* Notice: Important status changes. */
#define LOGN_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(NOTICE)) {                                       \
			break;                                                 \
		}                                                              \
		LOG_F(NOTICE, format, __VA_ARGS__);                            \
	} while (0)
#define LOGN(message) LOGN_F("%s", message)

/* Info: Normal work reports. */
#define LOGI_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(INFO)) {                                         \
			break;                                                 \
		}                                                              \
		LOG_F(INFO, format, __VA_ARGS__);                              \
	} while (0)
#define LOGI(message) LOGI_F("%s", message)

/* Debug: Extra information for debugging. */
#define LOGD_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(DEBUG)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(DEBUG, format, __VA_ARGS__);                             \
	} while (0)
#define LOGD(message) LOGD_F("%s", message)

/* Verbose: Details for inspecting specific issues. */
#define LOGV_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(VERBOSE)) {                                      \
			break;                                                 \
		}                                                              \
		LOG_F(VERBOSE, format, __VA_ARGS__);                           \
	} while (0)
#define LOGV(message) LOGV_F("%s", message)

#endif /* UTILS_SLOG_H */
