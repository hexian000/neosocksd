/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "memory.h"
#include "stream.h"
#include "utils/buffer.h"
#include "utils/class.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct memory_stream {
	struct stream s;
	unsigned char *buf;
	size_t bufsize;
	size_t *nwritten;
};
ASSERT_SUPER(struct stream, struct memory_stream, s);

static int
mem_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct memory_stream *restrict m = p;
	size_t n = *len;
	const size_t remain = m->bufsize;
	if (n > remain) {
		n = remain;
	}
	*buf = m->buf;
	m->buf += n, m->bufsize -= n;
	*len = n;
	return 0;
}

static int mem_write(void *p, const void *restrict buf, size_t *restrict len)
{
	struct memory_stream *restrict m = p;
	size_t n = *len;
	const size_t remain = m->bufsize;
	if (n > remain) {
		n = remain;
	}
	memcpy(m->buf, buf, n);
	m->buf += n, m->bufsize -= n;
	*len = n;
	size_t *restrict nwritten = m->nwritten;
	if (nwritten != NULL) {
		*nwritten += n;
	}
	return 0;
}

static struct stream *
io_memstream(void *buf, const size_t bufsize, size_t *nwritten)
{
	if (buf == NULL) {
		return NULL;
	}
	struct memory_stream *m = malloc(sizeof(struct memory_stream));
	if (m == NULL) {
		return NULL;
	}
	m->buf = buf;
	m->bufsize = bufsize;
	m->nwritten = nwritten;
	return &m->s;
}

struct stream *io_memreader(const void *buf, const size_t bufsize)
{
	struct stream *s = io_memstream((void *)buf, bufsize, NULL);
	if (s == NULL) {
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.direct_read = mem_direct_read,
	};
	*s = (struct stream){ &vftable, NULL };
	return s;
}

struct stream *io_memwriter(void *buf, const size_t bufsize, size_t *nwritten)
{
	struct stream *s = io_memstream(buf, bufsize, nwritten);
	if (s == NULL) {
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.write = mem_write,
	};
	*s = (struct stream){ &vftable, NULL };
	return s;
}

static int heap_write(void *p, const void *restrict buf, size_t *restrict len)
{
	struct stream *restrict s = p;
	struct vbuffer *restrict *restrict pvbuf = s->data;
	const size_t n = *len;
	const size_t expected = VBUF_LEN(*pvbuf) + n;
	(*pvbuf) = VBUF_APPEND(*pvbuf, buf, n);
	if (VBUF_LEN(*pvbuf) != expected) {
		return -1;
	}
	return 0;
}

static const struct stream_vftable vftable_heapwriter = {
	.write = heap_write,
};
struct stream *io_heapwriter(struct vbuffer **restrict pvbuf)
{
	if (pvbuf == NULL) {
		return NULL;
	}
	struct stream *s = malloc(sizeof(struct stream));
	if (s == NULL) {
		return NULL;
	}
	*s = (struct stream){ &vftable_heapwriter, pvbuf };
	return s;
}

int io_heapprintf(struct stream *restrict s, const char *restrict format, ...)
{
	assert(s->vftable == &vftable_heapwriter);
	struct vbuffer *restrict *restrict pvbuf = s->data;
	va_list args;
	va_start(args, format);
	(*pvbuf) = VBUF_VAPPENDF(*pvbuf, format, args);
	va_end(args);
	return 0;
}

struct buffered_stream {
	struct stream s;
	struct stream *base;
	int err;
	size_t bufsize;
	size_t pos, len;
	unsigned char buf[];
};
ASSERT_SUPER(struct stream, struct buffered_stream, s);

static int
buf_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	if (b->pos == b->len) {
		size_t n = b->bufsize;
		b->err = stream_read(b->base, b->buf, &n);
		if (n == 0) {
			*len = 0;
			const int err = b->err;
			b->err = 0;
			return err;
		}
	}
	*buf = b->buf + b->pos;
	*len = b->len - b->pos;
	b->pos = b->len = 0;
	const int err = b->err;
	b->err = 0;
	return err;
}

static int buf_read(void *p, void *restrict buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	size_t nread = *len;
	if (nread == 0) {
		if (b->pos < b->len) {
			*len = 0;
			return 0;
		}
		const int err = b->err;
		b->err = 0;
		return err;
	}
	if (b->pos == b->len) {
		if (b->err != 0) {
			const int err = b->err;
			b->err = 0;
			return err;
		}
		if (nread >= b->bufsize) {
			return stream_read(b->base, b->buf, len);
		}
		b->pos = b->len = 0;
		nread = b->bufsize;
		b->err = stream_read(b->base, b->buf, &nread);
		if (nread == 0) {
			*len = 0;
			const int err = b->err;
			b->err = 0;
			return err;
		}
		b->len += nread;
	}

	const unsigned char *src = b->buf;
	const size_t n = b->len - b->pos;
	memcpy(buf, src + b->pos, n);
	b->pos += n;
	*len = n;
	return 0;
}

static int buf_flush_(struct buffered_stream *restrict b)
{
	if (b->err != 0) {
		return b->err;
	}
	size_t len = b->len;
	if (len == 0) {
		return 0;
	}
	struct stream *restrict base = b->base;
	b->err = stream_write(base, b->buf, &len);
	if (len < b->len && b->err == 0) {
		/* short write */
		b->err = -1;
	}
	if (b->err != 0) {
		if (len > 0 && len < b->len) {
			memmove(b->buf, b->buf + len, b->len - len);
		}
		b->len -= len;
		return b->err;
	}
	b->len = 0;
	return 0;
}

static int buf_flush(void *p)
{
	struct buffered_stream *restrict b = p;
	int err = buf_flush_(b);
	if (err != 0) {
		return err;
	}
	return stream_flush(b->base);
}

static int buf_write(void *p, const void *restrict buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	const unsigned char *src = buf;
	size_t srclen = *len;
	size_t nwritten = 0;
	const size_t navail = b->bufsize - b->len;
	while (srclen > navail && b->err == 0) {
		size_t n;
		if (b->len == 0) {
			n = srclen;
			struct stream *restrict base = b->base;
			const int ret = stream_write(base, buf, &n);
			if (ret != 0) {
				return ret;
			}
		} else {
			n = navail;
			memcpy(b->buf + b->len, src, n);
			b->len += n;
			(void)buf_flush_(b); /* err is saved */
		}
		nwritten += n;
		src += n;
		srclen -= n;
	}
	if (b->err != 0) {
		*len = nwritten;
		return b->err;
	}
	memcpy(b->buf + b->len, src, srclen);
	b->len += srclen;
	*len = (nwritten += srclen);
	return 0;
}

static int buf_vprintf(void *p, const char *restrict format, va_list args)
{
	struct buffered_stream *restrict b = DOWNCAST(
		struct stream, struct buffered_stream, s, (struct stream *)p);
	int ret = buf_flush_(b);
	if (ret != 0) {
		return ret;
	}
	char *s = (char *)b->buf + b->len;
	size_t maxlen = b->bufsize - b->len;
	ret = vsnprintf(s, maxlen, format, args);
	if (ret < 0) {
		return ret;
	}
	if ((size_t)ret < maxlen) {
		b->len += (size_t)ret;
		return 0;
	}
	b->len = b->bufsize - 1;
	return 0;
}

static int rbuf_close(void *p)
{
	struct buffered_stream *restrict b = p;
	const int err = stream_close(b->base);
	free(b);
	return err;
}

static int wbuf_close(void *p)
{
	struct buffered_stream *restrict b = p;
	(void)buf_flush_(b);
	const int err = b->err;
	const int ret = stream_close(b->base);
	free(b);
	return err != 0 ? err : ret;
}

static struct stream *io_bufstream(struct stream *base, size_t bufsize)
{
	if (base == NULL) {
		return NULL;
	}
	struct buffered_stream *b =
		malloc(sizeof(struct buffered_stream) + bufsize);
	if (b == NULL) {
		stream_close(base);
		return NULL;
	}
	b->base = base;
	b->err = 0;
	b->bufsize = bufsize;
	b->pos = b->len = 0;
	return &b->s;
}

struct stream *io_bufreader(struct stream *base, const size_t bufsize)
{
	if (bufsize == 0) {
		return base;
	}
	struct stream *s = io_bufstream(base, bufsize);
	if (s == NULL) {
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.direct_read = buf_direct_read,
		.read = buf_read,
		.close = rbuf_close,
	};
	*s = (struct stream){ &vftable, NULL };
	return s;
}

static const struct stream_vftable vftable_bufwriter = {
	.write = buf_write,
	.flush = buf_flush,
	.close = wbuf_close,
};
struct stream *io_bufwriter(struct stream *base, const size_t bufsize)
{
	if (bufsize == 0) {
		return base;
	}
	struct stream *restrict s = io_bufstream(base, bufsize);
	if (s == NULL) {
		return NULL;
	}
	*s = (struct stream){ &vftable_bufwriter, NULL };
	return s;
}

int io_bufprintf(struct stream *restrict s, const char *restrict format, ...)
{
	assert(s->vftable == &vftable_bufwriter);
	va_list args;
	va_start(args, format);
	const int ret = buf_vprintf(s, format, args);
	va_end(args);
	return ret;
}

struct metered_stream {
	struct stream s;
	struct stream *base;
	size_t *meter;
};
ASSERT_SUPER(struct stream, struct metered_stream, s);

static int
metered_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct metered_stream *restrict m = p;
	const int ret = stream_direct_read(m->base, buf, len);
	if (m->meter != NULL) {
		*m->meter += *len;
	}
	return ret;
}

static int metered_read(void *p, void *restrict buf, size_t *restrict len)
{
	struct metered_stream *restrict m = p;
	const int ret = stream_read(m->base, buf, len);
	if (m->meter != NULL) {
		*m->meter += *len;
	}
	return ret;
}

static int
metered_write(void *p, const void *restrict buf, size_t *restrict len)
{
	struct metered_stream *restrict m = p;
	const int ret = stream_write(m->base, buf, len);
	if (m->meter != NULL) {
		*m->meter += *len;
	}
	return ret;
}

struct stream *io_metered(struct stream *base, size_t *meter)
{
	if (base == NULL) {
		return NULL;
	}
	struct metered_stream *m = malloc(sizeof(struct metered_stream));
	if (m == NULL) {
		stream_close(base);
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.direct_read = metered_direct_read,
		.read = metered_read,
		.write = metered_write,
	};
	m->s = (struct stream){ &vftable, NULL };
	m->base = base;
	m->meter = meter;
	return &m->s;
}
