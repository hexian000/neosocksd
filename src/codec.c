/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "codec.h"
#include "io/stream.h"
#include "utils/object.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include "miniz.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

struct deflate_stream {
	struct stream s;
	struct stream *base;
	tdefl_status status;
	tdefl_compressor deflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[IO_BUFSIZE];
};
ASSERT_SUPER(struct stream, struct deflate_stream, s);

static int deflate_write(void *p, const void *buf, size_t *restrict len)
{
	struct deflate_stream *restrict z = p;
	size_t nwritten = 0;
	const unsigned char *src = buf;
	size_t remain = *len;
	while (remain > 0 && z->status == TDEFL_STATUS_OKAY) {
		/* dst not full, deflate */
		if (z->dstlen < sizeof(z->dstbuf)) {
			size_t srclen = remain;
			unsigned char *dst = z->dstbuf + z->dstlen;
			size_t dstlen = sizeof(z->dstbuf) - z->dstlen;
			z->status = tdefl_compress(
				&z->deflator, src, &srclen, dst, &dstlen,
				TDEFL_NO_FLUSH);
			src += srclen, remain -= srclen;
			z->dstlen += dstlen;
			nwritten += srclen;
		}

		unsigned char *avail = z->dstbuf + z->dstpos;
		size_t n = z->dstlen - z->dstpos;
		const int ret = stream_write(z->base, avail, &n);
		z->dstpos += n;
		/* no more output, flip */
		if (z->dstpos == z->dstlen) {
			z->dstpos = z->dstlen = 0;
		}
		if (ret != 0) {
			return ret;
		}
	}
	*len = nwritten;
	if (z->status != TDEFL_STATUS_OKAY) {
		return z->status;
	}
	return 0;
}

static int deflate_close(void *p)
{
	struct deflate_stream *restrict z = p;
	int err = 0;
	do {
		unsigned char *buf = z->dstbuf + z->dstlen;
		size_t n = sizeof(z->dstbuf) - z->dstlen;
		z->status = tdefl_compress(
			&z->deflator, NULL, NULL, buf, &n, TDEFL_FINISH);
		z->dstlen += n;

		buf = z->dstbuf + z->dstpos;
		n = z->dstlen - z->dstpos;
		err = stream_write(z->base, buf, &n);
		z->dstpos += n;
		if (err != 0) {
			break;
		} else if (z->dstpos != z->dstlen) {
			err = -1; /* short write */
			break;
		}
		z->dstpos = z->dstlen = 0;

		if (z->status < TDEFL_STATUS_OKAY) {
			err = z->status;
			break;
		}
	} while (z->status != TDEFL_STATUS_DONE);
	const int ret = stream_close(z->base);
	if (err == 0) {
		err = ret;
	}
	free(z);
	return err;
}

static struct stream *deflate_writer(struct stream *base, const bool zlib)
{
	if (base == NULL) {
		return NULL;
	}
	struct deflate_stream *z = malloc(sizeof(struct deflate_stream));
	if (z == NULL) {
		stream_close(base);
		return NULL;
	}
	z->base = base;
	z->status = TDEFL_STATUS_OKAY;
	const int flags =
		(zlib ? TDEFL_WRITE_ZLIB_HEADER : 0) | TDEFL_DEFAULT_MAX_PROBES;
	const tdefl_status status = tdefl_init(&z->deflator, NULL, NULL, flags);
	if (status != TDEFL_STATUS_OKAY) {
		stream_close(base);
		free(z);
		return NULL;
	}
	z->dstpos = z->dstlen = 0;
	static const struct stream_vftable vftable = {
		.write = deflate_write,
		.close = deflate_close,
	};
	z->s = (struct stream){ &vftable, NULL };
	return &z->s;
}

struct stream *codec_zlib_writer(struct stream *base)
{
	return deflate_writer(base, true);
}

struct stream *codec_deflate_writer(struct stream *base)
{
	return deflate_writer(base, false);
}

struct inflate_stream {
	struct stream s;
	struct stream *base;
	int flags;
	tinfl_status status;
	tinfl_decompressor inflator;
	bool srceof : 1;
	size_t dstpos, dstlen;
	unsigned char dstbuf[TINFL_LZ_DICT_SIZE];
	size_t srcpos, srclen;
	unsigned char srcbuf[IO_BUFSIZE];
};
ASSERT_SUPER(struct stream, struct deflate_stream, s);

static int inflate_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct inflate_stream *restrict z = p;
	do {
		/* srcbuf is empty, input */
		if (!z->srceof && z->srcpos == z->srclen) {
			size_t n = sizeof(z->srcbuf);
			const int ret = stream_read(z->base, z->srcbuf, &n);
			z->srcpos = 0;
			z->srclen = n;
			if (ret != 0) {
				return ret;
			}
			if (n == 0) {
				z->srceof = true;
			}
		}

		/* dstbuf is full, wrap */
		if (z->dstpos == z->dstlen && z->dstlen == sizeof(z->dstbuf)) {
			z->dstpos = z->dstlen = 0;
		}

		/* srcbuf is not empty && dstbuf is not full, inflate */
		if (z->status > TINFL_STATUS_DONE && z->srcpos != z->srclen &&
		    z->dstlen < sizeof(z->dstbuf)) {
			const unsigned char *src = z->srcbuf + z->srcpos;
			size_t srclen = z->srclen - z->srcpos;
			unsigned char *dst = z->dstbuf + z->dstlen;
			size_t dstlen = sizeof(z->dstbuf) - z->dstlen;
			const int flags =
				z->flags |
				(z->srceof ? 0 : TINFL_FLAG_HAS_MORE_INPUT);
			z->status = tinfl_decompress(
				&z->inflator, src, &srclen, z->dstbuf, dst,
				&dstlen, flags);
			z->srcpos += srclen;
			z->dstlen += dstlen;
		}

		/* output available */
		if (z->dstpos < z->dstlen) {
			const size_t maxread = *len;
			size_t n = z->dstlen - z->dstpos;
			if (n > maxread) {
				n = maxread;
			}
			*buf = z->dstbuf + z->dstpos;
			*len = n;
			z->dstpos += n;
			return 0;
		}
	} while (z->status > TINFL_STATUS_DONE && !z->srceof);
	*len = 0;
	if (z->status != TINFL_STATUS_DONE) {
		return z->status;
	}
	return 0;
}

static int inflate_close(void *p)
{
	struct inflate_stream *restrict z = p;
	const int ret = stream_close(z->base);
	free(z);
	return ret;
}

static struct stream *inflate_reader(struct stream *base, const bool zlib)
{
	if (base == NULL) {
		return NULL;
	}
	struct inflate_stream *z = malloc(sizeof(struct inflate_stream));
	if (z == NULL) {
		stream_close(base);
		return NULL;
	}
	z->base = base;
	z->flags = zlib ? TINFL_FLAG_PARSE_ZLIB_HEADER : 0;
	z->status = TINFL_STATUS_NEEDS_MORE_INPUT;
	tinfl_init(&z->inflator);
	z->srceof = false;
	z->srcpos = z->srclen = 0;
	z->dstpos = z->dstlen = 0;
	static const struct stream_vftable vftable = {
		.direct_read = inflate_direct_read,
		.close = inflate_close,
	};
	z->s = (struct stream){ &vftable, NULL };
	return &z->s;
}

struct stream *codec_zlib_reader(struct stream *base)
{
	return inflate_reader(base, true);
}

struct stream *codec_inflate_reader(struct stream *base)
{
	return inflate_reader(base, false);
}

/* RFC 1952 */
enum gzip_flags {
	GZIP_FTEXT = 1 << 0,
	GZIP_FHCRC = 1 << 1,
	GZIP_FEXTRA = 1 << 2,
	GZIP_FNAME = 1 << 3,
	GZIP_FCOMMENT = 1 << 4,
};

const void *gzip_unbox(const void *p, size_t *restrict len)
{
	const unsigned char *restrict b = p;
	size_t n = *len;
	if (n < 10) {
		return NULL;
	}
	struct {
		uint8_t id1, id2;
		uint8_t cm, flg;
		uint32_t mtime;
		uint8_t xfl, os;
	} header = {
		.id1 = read_uint8(b + 0),
		.id2 = read_uint8(b + 1),
		.cm = read_uint8(b + 2),
		.flg = read_uint8(b + 3),
		.mtime = read_uint32_le(b + 4),
		.xfl = read_uint8(b + 8),
		.os = read_uint8(b + 9),
	};
	if (header.id1 != 0x1f || header.id2 != 0x8b || header.cm != 0x08) {
		LOGD("gzip: unsupported header");
		return NULL;
	}
	b += 10, n -= 10;
	if (header.flg & GZIP_FEXTRA) {
		if (n < 2) {
			return NULL;
		}
		uint16_t xlen = read_uint16_le(b);
		b += 2, n -= 2;
		if (n < xlen) {
			return NULL;
		}
		b += xlen, n -= xlen;
	}
	if (header.flg & GZIP_FNAME) {
		const char *name = (char *)b;
		const size_t slen = strnlen(name, n) + 1;
		if (slen >= n) {
			return NULL;
		}
		b += slen, n -= slen;
		LOGD_F("gzip: NAME \"%s\"", name);
	}
	if (header.flg & GZIP_FCOMMENT) {
		const char *comment = (char *)b;
		const size_t slen = strnlen(comment, n) + 1;
		if (slen >= n) {
			return NULL;
		}
		b += slen, n -= slen;
		LOGD_F("gzip: COMMENT \"%s\"", comment);
	}
	if (header.flg & GZIP_FHCRC) {
		if (n < 2) {
			return NULL;
		}
		const size_t hlen = *len - n;
		const uint16_t hcrc = read_uint16_le(b);
		b += 2, n -= 2;
		if (hcrc != (uint16_t)mz_crc32(0, p, hlen)) {
			LOGD("gzip: HCRC mismatch");
			return NULL;
		}
	}
	if (n < 8) {
		LOGD("gzip: short tailer");
		return NULL;
	}
	struct {
		uint32_t crc, isize;
	} tailer = {
		.crc = read_uint32_le(b + n - 8),
		.isize = read_uint32_le(b + n - 4),
	};
	LOGD_F("gzip: original size %" PRIu32 " bytes", tailer.isize);
	*len = n - 8;
	return b;
}
