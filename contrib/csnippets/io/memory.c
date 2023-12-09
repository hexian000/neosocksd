#include "memory.h"
#include "stream.h"
#include "utils/buffer.h"
#include "utils/object.h"

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

static int mem_direct_read(void *p, const void **buf, size_t *restrict len)
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

static int mem_write(void *p, const void *buf, size_t *restrict len)
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

static int mem_close(void *p)
{
	free(p);
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
		.close = mem_close,
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
		.close = mem_close,
	};
	*s = (struct stream){ &vftable, NULL };
	return s;
}

static int heap_write(void *p, const void *buf, size_t *restrict len)
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

struct stream *io_heapwriter(struct vbuffer **pvbuf)
{
	if (pvbuf == NULL) {
		return NULL;
	}
	struct stream *s = malloc(sizeof(struct stream));
	if (s == NULL) {
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.write = heap_write,
	};
	*s = (struct stream){ &vftable, pvbuf };
	return s;
}

struct buffered_stream {
	struct stream s;
	struct stream *base;
	size_t bufsize;
	int err;
	union {
		struct {
			size_t pos, len;
		} r;
		struct {
			size_t len;
		} w;
	};
	unsigned char buf[];
};
ASSERT_SUPER(struct stream, struct buffered_stream, s);

static int buf_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	if (b->r.pos == b->r.len) {
		size_t n = b->bufsize;
		b->err = stream_read(b->base, b->buf, &n);
		if (n == 0) {
			*len = 0;
			const int err = b->err;
			b->err = 0;
			return err;
		}
	}
	*buf = b->buf + b->r.pos;
	*len = b->r.len - b->r.pos;
	const int err = b->err;
	b->err = 0;
	return err;
}

static int buf_read(void *p, void *buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	size_t nread = *len;
	if (nread == 0) {
		if (b->r.pos < b->r.len) {
			*len = 0;
			return 0;
		}
		const int err = b->err;
		b->err = 0;
		return err;
	}
	if (b->r.pos == b->r.len) {
		if (b->err != 0) {
			const int err = b->err;
			b->err = 0;
			return err;
		}
		if (nread >= b->bufsize) {
			return stream_read(b->base, b->buf, len);
		}
		b->r.pos = b->r.len = 0;
		nread = b->bufsize;
		b->err = stream_read(b->base, b->buf, &nread);
		if (nread == 0) {
			*len = 0;
			const int err = b->err;
			b->err = 0;
			return err;
		}
		b->r.len += nread;
	}

	const unsigned char *src = b->buf;
	const size_t n = b->r.len - b->r.pos;
	memcpy(buf, src + b->r.pos, n);
	b->r.pos += n;
	*len = n;
	return 0;
}

static int buf_flush_(struct buffered_stream *restrict b)
{
	if (b->err != 0) {
		return b->err;
	}
	size_t len = b->w.len;
	if (len == 0) {
		return 0;
	}
	struct stream *restrict base = b->base;
	b->err = stream_write(base, b->buf, &len);
	if (len < b->w.len && b->err == 0) {
		/* short write */
		b->err = -1;
	}
	if (b->err != 0) {
		if (len > 0 && len < b->w.len) {
			memmove(b->buf, b->buf + len, b->w.len - len);
		}
		b->w.len -= len;
		return b->err;
	}
	b->w.len = 0;
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

static int buf_write(void *p, const void *buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	const unsigned char *src = buf;
	size_t srclen = *len;
	size_t nwritten = 0;
	const size_t navail = b->bufsize - b->w.len;
	while (srclen > navail && b->err == 0) {
		size_t n;
		if (b->w.len == 0) {
			n = srclen;
			struct stream *restrict base = b->base;
			const int ret = stream_write(base, buf, &n);
			if (ret != 0) {
				return ret;
			}
		} else {
			n = navail;
			memcpy(b->buf + b->w.len, src, n);
			b->w.len += n;
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
	memcpy(b->buf + b->w.len, src, srclen);
	b->w.len += srclen;
	*len = (nwritten += srclen);
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
	if (bufsize == 0) {
		bufsize = IO_BUFSIZE;
	}
	struct buffered_stream *b =
		malloc(sizeof(struct buffered_stream) + bufsize);
	if (b == NULL) {
		return NULL;
	}
	b->base = base;
	b->bufsize = bufsize;
	return &b->s;
}

struct stream *io_bufreader(struct stream *base, const size_t bufsize)
{
	struct stream *s = io_bufstream(base, bufsize);
	if (s == NULL) {
		stream_close(base);
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

struct stream *io_bufwriter(struct stream *base, const size_t bufsize)
{
	struct stream *restrict s = io_bufstream(base, bufsize);
	if (s == NULL) {
		stream_close(base);
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.write = buf_write,
		.flush = buf_flush,
		.close = wbuf_close,
	};
	*s = (struct stream){ &vftable, NULL };
	return s;
}
