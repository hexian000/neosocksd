/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_MIME_H
#define NET_MIME_H

/**
 * @defgroup mime
 * @brief RFC 2045: Multipurpose Internet Mail Extensions (MIME)
 * @{
 */

/**
 * @brief Parse a media type string.
 * @details No allocations, the raw message until next position is destructed.
 * RFC 2045 Section 5.1 makes type and subtype case-insensitive; both are
 * lowercased in place.
 * @param s MIME string.
 * @param[out] type Type value.
 * @param[out] subtype Subtype value.
 * @return The start position of next parsing, or NULL when parsing failed.
 */
char *mime_parse(char *s, char **restrict type, char **restrict subtype);

/**
 * @brief Parse a media type parameter.
 * @details No allocations, the raw message until next position is destructed.
 * RFC 2045 Section 5.1 makes the attribute name case-insensitive; it is
 * lowercased in place, while the value keeps its case and a quoted value is
 * unquoted and unescaped in place.
 *
 * RFC 2231 parameters are not supported: an attribute name containing `'*'` --
 * an extended value (`name*=charset'lang'value`, Section 4) or a continuation
 * (`name*0=`, Section 3) -- is declined and reported as a parse failure.
 * @param s param string, usually the return value of mime_parse.
 * @param[out] key Parameter attribute name, or NULL when finished.
 * @param[out] value Parameter value, or NULL when finished.
 * @return The start position of next parsing, or NULL when parsing failed or
 * an RFC 2231 parameter was declined.
 */
char *mime_parseparam(char *s, char **restrict key, char **restrict value);

/** @} */

#endif /* NET_MIME_H */
