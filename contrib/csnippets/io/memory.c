/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "memory.h"

#include "io.h"
#include "meta/class.h"
#include "stream.h"
#include "utils/buffer.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct memory_stream {
	struct stream s;
	/* the reader only ever advances this pointer (mem_direct_read never
	 * writes through it) while the writer writes through it; the union lets
	 * the reader keep a const view so io_memreader need not cast away the
	 * caller's const */
	union {
		unsigned char *w; /* io_memwriter: written through */
		const unsigned char *r; /* io_memreader: only advanced */
	} buf;
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
	*buf = m->buf.r;
	m->buf.r += n, m->bufsize -= n;
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
	memcpy(m->buf.w, buf, n);
	m->buf.w += n, m->bufsize -= n;
	*len = n;
	size_t *restrict nwritten = m->nwritten;
	if (nwritten != NULL) {
		*nwritten += n;
	}
	return 0;
}

static struct memory_stream *
io_memstream(const size_t bufsize, size_t *nwritten)
{
	struct memory_stream *m = malloc(sizeof(struct memory_stream));
	if (m == NULL) {
		return NULL;
	}
	m->bufsize = bufsize;
	m->nwritten = nwritten;
	return m;
}

struct stream *io_memreader(const void *buf, const size_t bufsize)
{
	if (buf == NULL) {
		return NULL;
	}
	struct memory_stream *m = io_memstream(bufsize, NULL);
	if (m == NULL) {
		return NULL;
	}
	m->buf.r = buf;
	static const struct stream_vftable vftable = {
		.direct_read = mem_direct_read,
	};
	m->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
	return &m->s;
}

struct stream *io_memwriter(void *buf, const size_t bufsize, size_t *nwritten)
{
	if (buf == NULL) {
		return NULL;
	}
	struct memory_stream *m = io_memstream(bufsize, nwritten);
	if (m == NULL) {
		return NULL;
	}
	m->buf.w = buf;
	static const struct stream_vftable vftable = {
		.write = mem_write,
	};
	m->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
	return &m->s;
}

static int heap_write(void *p, const void *restrict buf, size_t *restrict len)
{
	struct stream *restrict s = p;
	struct vbuffer *restrict *restrict pvbuf = (struct vbuffer **)s->data;
	const size_t n = *len;
	const size_t before = VBUF_LEN(*pvbuf);
	VBUF_APPEND(*pvbuf, buf, n);
	/* report the true number of bytes appended, even on a partial/failed
	 * append, so callers know how much was actually persisted */
	const size_t appended = VBUF_LEN(*pvbuf) - before;
	*len = appended;
	if (appended != n) {
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
	*s = (struct stream){
		.vftable = &vftable_heapwriter,
		.data = (void *)pvbuf,
	};
	return s;
}

int io_heapprintf(struct stream *restrict s, const char *restrict format, ...)
{
	assert(s->vftable == &vftable_heapwriter);
	struct vbuffer *restrict *restrict pvbuf = (struct vbuffer **)s->data;
	va_list args;
	va_start(args, format);
	const int ret = VBUF_VAPPENDF(*pvbuf, format, args);
	va_end(args);
	if (ret < 0) {
		return ret;
	}
	if (VBUF_HAS_OOM(*pvbuf)) {
		/* growth failed during the call: vappendf still returns the
		 * would-be count while truncating the stored data and marking
		 * the vbuffer OOM, so report the truncation as an error */
		return -1;
	}
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
		if (b->err != 0) {
			*len = 0;
			const int err = b->err;
			b->err = 0;
			return err;
		}
		b->pos = b->len = 0;
		size_t n = b->bufsize;
		b->err = stream_read(b->base, b->buf, &n);
		b->len = n;
		if (n == 0) {
			*len = 0;
			const int err = b->err;
			b->err = 0;
			return err;
		}
	}
	/* never report more than the caller's requested max, even if more
	 * is already buffered; the remainder stays buffered for next time */
	const size_t want = *len;
	const size_t avail = b->len - b->pos;
	const size_t n = avail < want ? avail : want;
	*buf = b->buf + b->pos;
	*len = n;
	b->pos += n;
	return 0;
}

static int buf_read(void *p, void *restrict buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	const size_t want = *len;
	if (want == 0) {
		if (b->pos < b->len) {
			*len = 0;
			return 0;
		}
		const int err = b->err;
		b->err = 0;
		return err;
	}
	unsigned char *restrict dst = buf;
	size_t nread = 0;
	/* keep refilling until the caller's buffer is full or the base runs
	 * dry; stream_read's contract lets the caller read a short return as
	 * EOF, so stopping on a partial buffer would truncate the stream */
	while (nread < want) {
		const size_t avail = b->len - b->pos;
		if (avail > 0) {
			const size_t remain = want - nread;
			const size_t n = avail < remain ? avail : remain;
			memcpy(dst + nread, b->buf + b->pos, n);
			b->pos += n;
			nread += n;
			continue;
		}
		if (b->err != 0) {
			break;
		}
		const size_t remain = want - nread;
		if (remain >= b->bufsize) {
			/* the remainder alone fills the internal buffer; read
			 * straight into the caller's to skip a copy */
			size_t n = remain;
			b->err = stream_read(b->base, dst + nread, &n);
			nread += n;
			if (n == 0) {
				break;
			}
			continue;
		}
		b->pos = b->len = 0;
		size_t n = b->bufsize;
		b->err = stream_read(b->base, b->buf, &n);
		b->len = n;
		if (n == 0) {
			break;
		}
	}
	*len = nread;
	if (nread == 0) {
		/* clear after reporting so a later read retries the base,
		 * mirroring buf_direct_read / buf_peek */
		const int err = b->err;
		b->err = 0;
		return err;
	}
	/* hand back the valid bytes now and defer any stashed error until the
	 * buffer drains, mirroring buf_direct_read / buf_peek */
	return 0;
}

static int buf_peek(void *p, const void **restrict buf, size_t *restrict len)
{
	struct buffered_stream *restrict b = p;
	if (b->pos < b->len) {
		*buf = b->buf + b->pos;
		if (*len > b->len - b->pos) {
			*len = b->len - b->pos;
		}
		return 0;
	}
	if (b->err != 0) {
		/* clear after reporting so a later peek retries the base,
		 * mirroring buf_read / buf_direct_read */
		*len = 0;
		const int err = b->err;
		b->err = 0;
		return err;
	}
	b->pos = 0;
	b->len = 0;
	size_t n = b->bufsize;
	const size_t req = (*len < n) ? *len : n;
	b->err = stream_read(b->base, b->buf, &n);
	b->len = n;
	*buf = b->buf;
	*len = (req < n) ? req : n;
	if (n == 0) {
		/* base returned no data; clear after reporting the error so the
		 * next peek retries, mirroring buf_read / buf_direct_read */
		const int err = b->err;
		b->err = 0;
		return err;
	}
	/* the base returned data together with a possible stashed error: hand
	 * back the valid peeked bytes now and defer the error (left in b->err)
	 * until the buffer drains, mirroring buf_read / buf_direct_read rather
	 * than reporting an error alongside good data */
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
	const int err = buf_flush_(b);
	if (err != 0) {
		/* clear the stashed error after reporting it so a subsequent
		 * flush retries the residual data instead of failing forever */
		b->err = 0;
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
	size_t navail = b->bufsize - b->len;
	while (srclen > navail && b->err == 0) {
		size_t n;
		if (b->len == 0) {
			n = srclen;
			struct stream *restrict base = b->base;
			const int ret = stream_write(base, src, &n);
			if (ret != 0) {
				/* report bytes consumed so far (prior iterations
				 * plus whatever the base accepted this call) */
				*len = nwritten + n;
				return ret;
			}
			if (n == 0) {
				/* base accepted nothing; retrying would
				 * spin forever, so treat it as a short
				 * write like buf_flush_ does */
				b->err = -1;
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
		navail = b->bufsize - b->len;
	}
	if (b->err != 0) {
		/* clear after reporting so a subsequent write retries the
		 * residual instead of returning the stale error forever */
		const int err = b->err;
		b->err = 0;
		*len = nwritten;
		return err;
	}
	memcpy(b->buf + b->len, src, srclen);
	b->len += srclen;
	nwritten += srclen;
	*len = nwritten;
	return 0;
}

static int buf_vprintf(void *p, const char *restrict format, va_list args)
{
	struct buffered_stream *restrict b = DOWNCAST(
		struct stream, struct buffered_stream, s, (struct stream *)p);
	int ret = buf_flush_(b);
	if (ret != 0) {
		/* clear after reporting so a subsequent call retries the residual
		 * instead of returning the stale error forever, matching
		 * buf_write / buf_flush */
		b->err = 0;
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
	if (bufsize > SIZE_MAX - sizeof(struct buffered_stream)) {
		stream_close(base);
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

static const struct stream_vftable vftable_bufreader = {
	.direct_read = buf_direct_read,
	.read = buf_read,
	.close = rbuf_close,
};

struct stream *io_bufreader(struct stream *base, size_t bufsize)
{
	if (bufsize == 0) {
		bufsize = IO_BUFSIZE;
	}
	struct stream *s = io_bufstream(base, bufsize);
	if (s == NULL) {
		return NULL;
	}
	*s = (struct stream){
		.vftable = &vftable_bufreader,
		.data = NULL,
	};
	return s;
}

int io_bufpeek(
	struct stream *restrict s, const void **restrict buf,
	size_t *restrict len)
{
	assert(s->vftable == &vftable_bufreader);
	return buf_peek(s, buf, len);
}

static const struct stream_vftable vftable_bufwriter = {
	.write = buf_write,
	.flush = buf_flush,
	.close = wbuf_close,
};
struct stream *io_bufwriter(struct stream *base, size_t bufsize)
{
	if (bufsize == 0) {
		bufsize = IO_BUFSIZE;
	}
	struct stream *restrict s = io_bufstream(base, bufsize);
	if (s == NULL) {
		return NULL;
	}
	*s = (struct stream){
		.vftable = &vftable_bufwriter,
		.data = NULL,
	};
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
	/* *len is the transferred-byte count per the stream contract (accurate
	 * even on an error return that also delivered data), so count it
	 * unconditionally */
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

static int metered_flush(void *p)
{
	struct metered_stream *restrict m = p;
	return stream_flush(m->base);
}

static int metered_close(void *p)
{
	struct metered_stream *restrict m = p;
	const int ret = stream_close(m->base);
	free(m);
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
	/* only advertise direct_read when the base actually supports it, so a
	 * metered wrapper over a read-only stream (e.g. io_filereader) does not
	 * forward direct_read to a NULL base entry */
	static const struct stream_vftable vftable_direct = {
		.direct_read = metered_direct_read,
		.read = metered_read,
		.write = metered_write,
		.flush = metered_flush,
		.close = metered_close,
	};
	static const struct stream_vftable vftable_indirect = {
		.read = metered_read,
		.write = metered_write,
		.flush = metered_flush,
		.close = metered_close,
	};
	m->s = (struct stream){
		.vftable = (base->vftable->direct_read != NULL) ?
				   &vftable_direct :
				   &vftable_indirect,
		.data = NULL,
	};
	m->base = base;
	m->meter = meter;
	return &m->s;
}
