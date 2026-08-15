/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "mime.h"

#include "utils/ctype_ascii.h"

#include <string.h>

/* RFC 2045 tspecials, including the backslash that separates the two quoted
 * specials below ("()<>@,;:\ "/[]?=") */
#define istspecial(c) (!!strchr("()<>@,;:\\\"/[]?=", (c)))
#define istoken(c)                                                             \
	(32u < (unsigned char)(c) && (unsigned char)(c) < 127u &&              \
	 !istspecial(c))

/* Skip a run of RFC 822 linear white space and return the first byte past it.
 * Only SP and HT are LWSP-chars; a CRLF is whitespace solely when it folds a
 * following LWSP-char. Any other byte (a bare CR/LF, VT, FF, DEL, ...) ends the
 * run and is left in place for the caller's token/separator check to reject. */
static char *skip_lwsp(char *restrict s)
{
	for (;;) {
		if (isblank((unsigned char)*s)) {
			s++;
			continue;
		}
		if (s[0] == '\r' && s[1] == '\n' &&
		    isblank((unsigned char)s[2])) {
			s += 2;
			continue;
		}
		break;
	}
	return s;
}

/* Trim leading and trailing linear white space in place, returning the first
 * non-LWSP byte. Trailing whitespace is peeled as whole LWSP runs (folds
 * included), so a stray control byte at either edge survives to be rejected. */
static char *trim_lwsp(char *restrict s)
{
	s = skip_lwsp(s);
	char *end = s;
	for (char *p = s; *p != '\0';) {
		char *const ws = skip_lwsp(p);
		if (ws != p) {
			p = ws;
			continue;
		}
		p++;
		end = p;
	}
	*end = '\0';
	return s;
}

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
	*type = strlower(trim_lwsp(s));
	*subtype = strlower(trim_lwsp(slash + 1));
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
	s = skip_lwsp(end);
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
	rest = skip_lwsp(rest);
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
				/* a quoted-pair may not smuggle in a control
				 * byte the unescaped path would reject */
				if (iscntrl(ch) && ch != '\t') {
					return NULL;
				}
			}
			break;
		default:
			/* Reject every control byte, not just CR and LF.
			 * RFC 822 qtext tolerates most CTLs, but the tree's
			 * other parsers (http_parsehdr, url.c's unescape) treat
			 * a raw control byte in decoded text as an injection
			 * vector and reject it; a value handed to a direct
			 * caller of this parser must not be held to a weaker
			 * rule just because the HTTP pipeline would have
			 * filtered it first. HT stays allowed, as it does
			 * there. */
			if (iscntrl(ch) && ch != '\t') {
				return NULL;
			}
			break;
		}
		*w++ = ch;
	}
	return NULL;
}

static char *parse_param(char *s, char **restrict key, char **restrict value)
{
	char *next = skip_lwsp(s);
	if (*next == '\0') {
		*key = *value = NULL;
		return next;
	}
	next = parse_key(next, key);
	if (next == NULL) {
		return NULL;
	}
	*key = strlower(*key);

	next = skip_lwsp(next);
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
