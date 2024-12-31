/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_MIME_H
#define NET_MIME_H

#include <stddef.h>

/**
 * @defgroup mime
 * @brief RFC 2045: Multipurpose Internet Mail Extensions (MIME)
 * @{
 */

/**
 * @brief Parse a media type string.
 * @details No allocations, the raw message until next position is destructed.
 * @param s MIME string.
 * @param[out] type Type value.
 * @param[out] value Subtype value.
 * @return The start position of next parsing, or NULL when parsing failed.
 */
char *mime_parse(char *s, char **type, char **subtype);

/**
 * @brief Parse a media type parameter.
 * @details No allocations, the raw message until next position is destructed.
 * @param s param string, usually the return value of mime_parse.
 * @param[out] key Parameter attribute name, or NULL when finished.
 * @param[out] value Parameter value, or NULL when finished.
 * @return The start position of next parsing, or NULL when parsing failed.
 */
char *mime_parseparam(char *s, char **key, char **value);

/** @} */

#endif /* NET_MIME_H */
