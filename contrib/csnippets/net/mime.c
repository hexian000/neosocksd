/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mime.h"

#include <ctype.h>
#include <string.h>

/* RFC 2045 */
#define istspecial(c) (!!strchr("()<>@,;:\"/[]?=", (c)))
#define istoken(c) (!iscntrl(c) && !istspecial(c))

static char *strtolower(char *s)
{
	for (char *restrict p = s; *p; p++) {
		*p = tolower(*p);
	}
	return s;
}

static char *strtrimleftspace(char *restrict s)
{
	for (; *s && isspace(*s); s++) {
	}
	return s;
}

static char *strtrimrightspace(char *restrict s)
{
	char *restrict e = s + strlen(s) - 1;
	for (; s < e && isspace(*e); e--) {
		*e = '\0';
	}
	return s;
}

static char *strtrimspace(char *s)
{
	return strtrimrightspace(strtrimleftspace(s));
}

char *mime_parse(char *s, char **type, char **subtype)
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
	*type = strtolower(strtrimspace(s));
	*subtype = strtolower(strtrimspace(slash + 1));
	return next;
}

static char *next_token(char *s)
{
	char *restrict sep;
	for (sep = s; *sep && istoken(*sep); sep++) {
	}
	return sep;
}

static char *parse_key(char *s, char **key)
{
	*key = s;
	s = next_token(s);
	if (*s != '=') {
		return NULL;
	}
	*s = '\0';
	return s + 1;
}

static char *parse_value(char *s, char **value)
{
	if (*s != '\"') {
		*value = s;
		s = next_token(s);
		if (*s == '\0') {
			return s;
		} else if (*s != ';') {
			return NULL;
		}
		*s = '\0';
		return s + 1;
	}
	for (char *r = s + 1, *w = s + 1; *r; r++, w++) {
		char ch = *r;
		switch (ch) {
		case '\"':
			r = strtrimleftspace(r + 1);
			if (*r == ';') {
				r++;
			}
			*w = '\0';
			*value = s + 1;
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
	*key = strtolower(*key);

	next = strtrimleftspace(next);
	next = parse_value(next, value);
	if (next == NULL) {
		return NULL;
	}
	*value = strtolower(*value);
	return next;
}

char *mime_parseparam(char *buf, char **restrict key, char **restrict value)
{
	char *next = parse_param(buf, key, value);
	if (next == NULL) {
		return NULL;
	} else if (*key == NULL) {
		return next;
	}
	char *star = strchr(*key, '*');
	if (star != NULL) {
		/* continuations are not supported */
		return NULL;
	}
	return next;
}
