/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "buffer.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int buf_vappendf(struct buffer *restrict buf, const char *format, va_list args)
{
	char *b = (char *)(buf->data + buf->len);
	const size_t maxlen = buf->cap - buf->len;
	if (maxlen == 0) {
		return 0;
	}
	const int ret = vsnprintf(b, maxlen, format, args);
	if (ret > 0) {
		buf->len += MIN((size_t)ret, maxlen - 1);
	}
	return ret;
}

int buf_appendf(struct buffer *restrict buf, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	const int ret = buf_vappendf(buf, format, args);
	va_end(args);
	return ret;
}

struct vbuffer *
vbuf_grow(struct vbuffer *restrict vbuf, const size_t want, const size_t maxcap)
{
	size_t cap = (vbuf != NULL) ? vbuf->cap : 0;
	if (want <= cap || cap >= maxcap) {
		return vbuf;
	}
	const size_t threshold1 = 256;
	const size_t threshold2 = 4096;
	do {
		size_t grow;
		if (cap < threshold1) {
			grow = threshold1;
		} else if (cap < threshold2) {
			grow = cap;
		} else {
			grow = cap / 4 + 3 * threshold2 / 4;
		}
		if (grow > maxcap || cap >= maxcap - grow) {
			/* overflow */
			cap = want;
			break;
		}
		cap += grow;
	} while (cap < want);

	struct vbuffer *restrict newbuf =
		realloc(vbuf, sizeof(struct vbuffer) + cap);
	if (newbuf == NULL && want < cap) {
		/* retry with minimal required capacity */
		cap = want;
		newbuf = realloc(vbuf, sizeof(struct vbuffer) + cap);
		if (newbuf == NULL) {
			return vbuf;
		}
	}
	newbuf->cap = cap;
	return newbuf;
}

struct vbuffer *
vbuf_append(struct vbuffer *restrict vbuf, const void *data, size_t n)
{
	if (n == 0) {
		return vbuf;
	}
	size_t want = n;
	if (vbuf != NULL) {
		want += vbuf->len;
		vbuf = vbuf_grow(vbuf, want, SIZE_MAX);
		if (vbuf->cap < want) {
			return vbuf;
		}
	} else {
		vbuf = vbuf_alloc(NULL, want);
		if (vbuf == NULL) {
			return NULL;
		}
	}
	(void)memcpy(vbuf->data + vbuf->len, data, n);
	vbuf->len += n;
	return vbuf;
}

struct vbuffer *
vbuf_vappendf(struct vbuffer *restrict vbuf, const char *format, va_list args)
{
	char *b = NULL;
	size_t maxlen = 0;
	if (vbuf != NULL) {
		b = (char *)(vbuf->data + vbuf->len);
		maxlen = vbuf->cap - vbuf->len;
	}

	va_list args0;
	va_copy(args0, args);
	int ret = vsnprintf(b, maxlen, format, args0);
	va_end(args0);
	if (ret <= 0) {
		return vbuf;
	}
	size_t want = (size_t)ret + (size_t)1;
	if (vbuf != NULL) {
		want += vbuf->len;
		if (want <= vbuf->cap) {
			/* first try success */
			vbuf->len += (size_t)ret;
			return vbuf;
		}
		vbuf = vbuf_grow(vbuf, want, SIZE_MAX);
		if (vbuf->cap < want) {
			return vbuf;
		}
	} else {
		vbuf = vbuf_alloc(NULL, want);
		if (vbuf == NULL) {
			return NULL;
		}
	}
	maxlen = vbuf->cap - vbuf->len;
	b = (char *)(vbuf->data + vbuf->len);
	ret = vsnprintf(b, maxlen, format, args);
	if (ret > 0) {
		vbuf->len += (size_t)ret;
	}
	return vbuf;
}

struct vbuffer *
vbuf_appendf(struct vbuffer *restrict vbuf, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	struct vbuffer *ret = vbuf_vappendf(vbuf, format, args);
	va_end(args);
	return ret;
}
