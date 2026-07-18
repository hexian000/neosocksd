/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mime.h"

#include "utils/ascii.h"

#include <string.h>

/* RFC 2045 */
#define istspecial(c) (!!strchr("()<>@,;:\"/[]?=", (c)))
#define istoken(c)                                                             \
	(32u < (unsigned char)(c) && (unsigned char)(c) < 127u &&              \
	 !istspecial(c))

char *mime_parse(char *s, char **restrict type, char **restrict subtype)
{
	char *next = strchr(s, ';');
	if (next == NULL) {
		next = s + strlen(s);
	} else {
		*next = '\0';
		next++;
	}
	char *slash = strchr(s, '/');
	if (slash == NULL) {
		return NULL;
	}
	*slash = '\0';
	*type = strlower(strtrimspace(s));
	*subtype = strlower(strtrimspace(slash + 1));
	/* RFC 6838: type and subtype must be non-empty token strings */
	if ((*type)[0] == '\0') {
		return NULL;
	}
	for (const char *p = *type; *p; p++) {
		if (!istoken(*p)) {
			return NULL;
		}
	}
	if ((*subtype)[0] == '\0') {
		return NULL;
	}
	for (const char *p = *subtype; *p; p++) {
		if (!istoken(*p)) {
			return NULL;
		}
	}
	return next;
}

static char *next_token(char *restrict s)
{
	char *sep;
	for (sep = s; *sep && istoken(*sep); sep++) {
	}
	return sep;
}

static char *parse_key(char *s, char **restrict key)
{
	*key = s;
	char *const end = next_token(s);
	if (end == *key) {
		/* the attribute name must have at least one token character,
		 * mirroring the type/subtype checks in mime_parse */
		return NULL;
	}
	/* LWSP may sit between the name and '=' (RFC 822 §3.1.4 free insertion),
	 * so skip it before deciding, and only then terminate the name -- as in
	 * end_value, trimming reads the byte the terminator would overwrite */
	s = strtrimleftspace(end);
	if (*s != '=') {
		return NULL;
	}
	*end = '\0';
	return s + 1;
}

/* Finish a parameter value after its last content byte: skip trailing LWSP,
 * require a ';' separator or end of string (rejecting stray trailing content),
 * consume the ';', then terminate the value at `end`.  `end` and `rest` may
 * alias -- they do for an unquoted value -- so `rest` is read before `end` is
 * written; the two are therefore not marked restrict. */
static char *end_value(char *end, char *rest)
{
	rest = strtrimleftspace(rest);
	if (*rest != ';' && *rest != '\0') {
		return NULL;
	}
	if (*rest == ';') {
		rest++;
	}
	*end = '\0';
	return rest;
}

static char *parse_value(char *s, char **restrict value)
{
	if (*s != '\"') {
		char *const end = next_token(s);
		if (end == s) {
			/* an unquoted value must have at least one token
			 * character; only a quoted "" may be empty */
			return NULL;
		}
		char *const next = end_value(end, end);
		if (next != NULL) {
			*value = s;
		}
		return next;
	}
	s++;
	/* unescape the quoted-string in place: w <= r always */
	unsigned char *w = (unsigned char *)s;
	for (char *r = s; *r; r++) {
		unsigned char ch = (unsigned char)*r;
		switch (ch) {
		case '\"': {
			char *const next = end_value((char *)w, r + 1);
			if (next != NULL) {
				*value = s;
			}
			return next;
		}
		case '\\':
			if (*(r + 1)) {
				r++;
				ch = (unsigned char)*r;
				if (ch == '\r' || ch == '\n') {
					return NULL;
				}
			}
			break;
		case '\r':
		case '\n':
			return NULL;
		default:
			break;
		}
		*w++ = ch;
	}
	return NULL;
}

static char *parse_param(char *s, char **restrict key, char **restrict value)
{
	char *next = strtrimleftspace(s);
	if (*next == '\0') {
		*key = *value = NULL;
		return next;
	}
	next = parse_key(next, key);
	if (next == NULL) {
		return NULL;
	}
	*key = strlower(*key);

	next = strtrimleftspace(next);
	next = parse_value(next, value);
	if (next == NULL) {
		return NULL;
	}
	return next;
}

char *mime_parseparam(char *s, char **restrict key, char **restrict value)
{
	char *next = parse_param(s, key, value);
	if (next == NULL) {
		return NULL;
	}
	if (*key == NULL) {
		return next;
	}
	char *star = strchr(*key, '*');
	if (star != NULL) {
		/* continuations are not supported */
		return NULL;
	}
	return next;
}
