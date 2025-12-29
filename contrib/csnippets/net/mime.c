/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mime.h"
#include "utils/ascii.h"

#include <string.h>

/* RFC 2045 */
#define istspecial(c) (!!strchr("()<>@,;:\"/[]?=", (c)))
#define istoken(c) ((unsigned char)(c) > 32u && !istspecial(c))

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
	return next;
}

static char *next_token(char *restrict s)
{
	char *sep;
	for (sep = s; *sep && istoken((unsigned char)*sep); sep++) {
	}
	return sep;
}

static char *parse_key(char *s, char **restrict key)
{
	*key = s;
	s = next_token(s);
	if (*s != '=') {
		return NULL;
	}
	*s = '\0';
	return s + 1;
}

static char *parse_value(char *s, char **restrict value)
{
	if (*s != '\"') {
		*value = s;
		s = next_token(s);
		if (*s == '\0') {
			return s;
		}
		if (*s != ';') {
			return NULL;
		}
		*s = '\0';
		return s + 1;
	}
	s++;
	unsigned char *w = (unsigned char *)s;
	for (char *r = s; *r; r++) {
		unsigned char ch = *r;
		switch (ch) {
		case '\"':
			r = strtrimleftspace(r + 1);
			if (*r == ';') {
				r++;
			}
			*w = '\0';
			*value = s;
			return r;
		case '\\':
			ch = *(r + 1);
			if (ch && istspecial(ch)) {
				r++;
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
	*value = strlower(*value);
	return next;
}

char *mime_parseparam(char *buf, char **restrict key, char **restrict value)
{
	char *next = parse_param(buf, key, value);
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
