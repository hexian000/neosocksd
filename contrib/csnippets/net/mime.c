#include "mime.h"

#include <ctype.h>
#include <string.h>

/* RFC 2045 */
#define istspecial(c) (!!strchr("()<>@,;:\"/[]?=", (c)))
#define istoken(c) (!iscntrl(c) && !istspecial(c))

static char *strtolower(char *restrict s)
{
	for (; *s; s++) {
		*s = tolower(*s);
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

static char *parse_token(char *s, char **token)
{
	char *restrict sep;
	for (sep = s; *sep && istoken(*sep); sep++) {
	}
	*sep = '\0';
	*token = s;
	return sep;
}

static char *parse_value(char *s, char **value)
{
	if (*s != '\"') {
		return parse_token(s, value);
	}
	for (char *r = s + 1, *w = s + 1; *r; r++, w++) {
		char ch = *r;
		switch (ch) {
		case '\"':
			*w = '\0';
			*value = s + 1;
			return ++r;
		case '\\':
			ch = *(r + 1);
			if (ch && istspecial(ch)) {
				r++;
			}
			break;
		case '\r':
		case '\n':
			*value = NULL;
			return s;
		default:
			break;
		}
		*w++ = ch;
	}
	*value = NULL;
	return s;
}

static char *parse_param(char *s, char **restrict key, char **restrict value)
{
	char *next = strtrimleftspace(s);
	if (*next != ';') {
		*key = *value = NULL;
		return next;
	}

	next = strtrimleftspace(next + 1);
	next = parse_token(next, key);
	*key = strtolower(*key);
	if (**key == '\0') {
		*key = *value = NULL;
		return next;
	}

	next = strtrimleftspace(next);
	if (*next != '=') {
		*key = *value = NULL;
		return next;
	}
	next = strtrimleftspace(next + 1);
	next = parse_value(next, value);
	*value = strtolower(*value);
	if (**value == '\0') {
		*key = *value = NULL;
		return next;
	}
	return next;
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

char *mime_parseparam(char *buf, char **restrict key, char **restrict value)
{
	char *next = parse_param(buf, key, value);
	if (*key == NULL) {
		next = strtrimspace(next);
		if (next[0] == '\0') {
			return next;
		} else if (next[0] == ';' && next[1] == '\0') {
			return next + 1;
		}
		return NULL;
	}

	char *star = strchr(*key, '*');
	if (star != NULL) {
		/* continuations are not supported */
		return NULL;
	}
	return next;
}
