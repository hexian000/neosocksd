/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "codec.h"

#include "io/file.h"
#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "miniz.h"
#include "utils/class.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		const int err = stream_write(z->base, avail, &n);
		z->dstpos += n;
		if (err != 0) {
			return err;
		}
		if (z->dstpos < z->dstlen) {
			return -1;
		}
		z->dstpos = z->dstlen = 0;
	}

	*len = nwritten;
	if (z->status != TDEFL_STATUS_OKAY) {
		return z->status;
	}
	return 0;
}

static int
deflate_flush_(struct deflate_stream *restrict z, const tdefl_flush flush)
{
	do {
		unsigned char *buf = z->dstbuf + z->dstlen;
		size_t n = sizeof(z->dstbuf) - z->dstlen;
		z->status = tdefl_compress(
			&z->deflator, NULL, NULL, buf, &n, flush);
		z->dstlen += n;

		buf = z->dstbuf + z->dstpos;
		n = z->dstlen - z->dstpos;
		const int err = stream_write(z->base, buf, &n);
		z->dstpos += n;
		if (err != 0) {
			return err;
		}
		if (z->dstpos < z->dstlen) {
			return -1;
		}
		z->dstpos = z->dstlen = 0;

		if (z->status < TDEFL_STATUS_OKAY) {
			return z->status;
		}
	} while (z->status != TDEFL_STATUS_DONE);
	return 0;
}

/* full flush: emit a sync point so the decompressor can restart here */
static int deflate_flush(void *p)
{
	struct deflate_stream *restrict z = p;
	int ret = deflate_flush_(z, TDEFL_FULL_FLUSH);
	if (ret == 0) {
		ret = stream_flush(z->base);
	}
	return ret;
}

static int deflate_close(void *p)
{
	struct deflate_stream *restrict z = p;
	const int flusherr = deflate_flush_(z, TDEFL_FINISH);
	const int err = stream_close(z->base);
	free(z);
	return flusherr != 0 ? flusherr : err;
}

static struct stream *deflate_writer(struct stream *base, const bool zlib)
{
	if (base == NULL) {
		return NULL;
	}

	struct deflate_stream *z = malloc(sizeof(struct deflate_stream));
	if (z == NULL) {
		LOGOOM();
		stream_close(base);
		return NULL;
	}

	static const struct stream_vftable vftable = {
		.write = deflate_write,
		.flush = deflate_flush,
		.close = deflate_close,
	};
	z->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
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
	return (struct stream *)z;
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
	bool srceof : 1;
	int srcerr;
	size_t srclen;
	const unsigned char *srcbuf;
	int flags;
	tinfl_status status;
	tinfl_decompressor inflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[TINFL_LZ_DICT_SIZE];
};
ASSERT_SUPER(struct stream, struct inflate_stream, s);

static int inflate_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct inflate_stream *restrict z = p;
	do {
		if (z->srclen == 0 && !z->srceof) {
			const void *srcbuf;
			size_t n = IO_BUFSIZE;
			z->srcerr = stream_direct_read(z->base, &srcbuf, &n);
			if (n < IO_BUFSIZE || z->srcerr != 0) {
				z->srceof = true;
			}
			z->srclen = n;
			z->srcbuf = srcbuf;
		}

		/* If output buffer is full, wrap around (sliding window) */
		if (z->dstpos == z->dstlen && z->dstlen == sizeof(z->dstbuf)) {
			z->dstpos = z->dstlen = 0;
		}

		if (z->srclen > 0 && z->dstlen < sizeof(z->dstbuf) &&
		    z->status > TINFL_STATUS_DONE) {
			const unsigned char *src = z->srcbuf;
			size_t srclen = z->srclen;
			unsigned char *dst = z->dstbuf + z->dstlen;
			size_t dstlen = sizeof(z->dstbuf) - z->dstlen;
			int flags = z->flags;

			if (!z->srceof) {
				flags |= TINFL_FLAG_HAS_MORE_INPUT;
			}

			z->status = tinfl_decompress(
				&z->inflator, src, &srclen, z->dstbuf, dst,
				&dstlen, flags);
			z->srcbuf += srclen;
			z->srclen -= srclen;
			z->dstlen += dstlen;
		}

		if (z->dstpos < z->dstlen) {
			const size_t maxread = *len;
			size_t n = z->dstlen - z->dstpos;
			if (n > maxread) {
				n = maxread;
			}
			*buf = z->dstbuf + z->dstpos;
			*len = n;
			z->dstpos += n;
			if (z->dstpos == z->dstlen) {
				return z->srcerr;
			}
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
	const int err = stream_close(z->base);
	free(z);
	return err;
}

static struct stream *inflate_reader(struct stream *base, const bool zlib)
{
	if (base == NULL) {
		return NULL;
	}

	/* Inflate reader requires direct_read capability - wrap if needed */
	if (base->vftable->direct_read == NULL) {
		base = io_bufreader(base, IO_BUFSIZE);
		if (base == NULL) {
			return NULL;
		}
	}

	struct inflate_stream *z = malloc(sizeof(struct inflate_stream));
	if (z == NULL) {
		LOGOOM();
		stream_close(base);
		return NULL;
	}

	static const struct stream_vftable vftable = {
		.direct_read = inflate_direct_read,
		.close = inflate_close,
	};
	z->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->base = base;
	z->srceof = false;
	z->srcerr = 0;
	z->srclen = 0;

	z->flags = zlib ? TINFL_FLAG_PARSE_ZLIB_HEADER : 0;
	z->status = TINFL_STATUS_NEEDS_MORE_INPUT;
	tinfl_init(&z->inflator);

	z->dstpos = z->dstlen = 0;
	return (struct stream *)z;
}

struct stream *codec_zlib_reader(struct stream *base)
{
	return inflate_reader(base, true);
}

struct stream *codec_inflate_reader(struct stream *base)
{
	return inflate_reader(base, false);
}

/* RFC 1952 - gzip format implementation */

/* same as deflate_stream, extended with running CRC-32 and
 * uncompressed byte count for the gzip trailer */
struct gzip_wstream {
	struct stream s;
	struct stream *base;
	bool finished : 1;
	tdefl_status status;
	tdefl_compressor deflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[IO_BUFSIZE];
	/* gzip trailer state */
	uint_least32_t crc;
	uint_least32_t isize;
};
ASSERT_SUPER(struct stream, struct gzip_wstream, s);

static int gzip_write(void *p, const void *buf, size_t *restrict len)
{
	struct gzip_wstream *restrict z = p;

	/* Start a new gzip member if the previous one was finished by flush */
	if (z->finished) {
		static const unsigned char header[10] = {
			0x1f, 0x8b, /* ID1, ID2 */
			0x08, /* CM: deflate */
			0x00, /* FLG: no optional fields */
			0,    0,    0, 0, /* MTIME: not set */
			0x00, /* XFL */
			0xff, /* OS: unknown */
		};
		size_t hlen = sizeof(header);
		const int herr = stream_write(z->base, header, &hlen);
		if (herr != 0 || hlen < sizeof(header)) {
			*len = 0;
			return herr != 0 ? herr : -1;
		}
		const tdefl_status status = tdefl_init(
			&z->deflator, NULL, NULL, TDEFL_DEFAULT_MAX_PROBES);
		if (status != TDEFL_STATUS_OKAY) {
			*len = 0;
			return status;
		}
		z->status = TDEFL_STATUS_OKAY;
		z->dstpos = z->dstlen = 0;
		z->finished = false;
	}

	size_t nwritten = 0;
	const unsigned char *src = buf;
	size_t remain = *len;

	while (remain > 0 && z->status == TDEFL_STATUS_OKAY) {
		if (z->dstlen < sizeof(z->dstbuf)) {
			size_t srclen = remain;
			unsigned char *dst = z->dstbuf + z->dstlen;
			size_t dstlen = sizeof(z->dstbuf) - z->dstlen;
			z->status = tdefl_compress(
				&z->deflator, src, &srclen, dst, &dstlen,
				TDEFL_NO_FLUSH);
			z->crc = (uint_least32_t)mz_crc32(z->crc, src, srclen);
			z->isize += (uint_least32_t)srclen;
			src += srclen, remain -= srclen;
			z->dstlen += dstlen;
			nwritten += srclen;
		}

		unsigned char *avail = z->dstbuf + z->dstpos;
		size_t n = z->dstlen - z->dstpos;
		const int err = stream_write(z->base, avail, &n);
		z->dstpos += n;
		if (err != 0) {
			return err;
		}
		if (z->dstpos < z->dstlen) {
			return -1;
		}
		z->dstpos = z->dstlen = 0;
	}

	*len = nwritten;
	if (z->status != TDEFL_STATUS_OKAY) {
		return z->status;
	}
	return 0;
}

static int gzip_flush_(struct gzip_wstream *restrict z, const tdefl_flush flush)
{
	do {
		unsigned char *buf = z->dstbuf + z->dstlen;
		size_t n = sizeof(z->dstbuf) - z->dstlen;
		z->status = tdefl_compress(
			&z->deflator, NULL, NULL, buf, &n, flush);
		z->dstlen += n;

		buf = z->dstbuf + z->dstpos;
		n = z->dstlen - z->dstpos;
		const int err = stream_write(z->base, buf, &n);
		z->dstpos += n;
		if (err != 0) {
			return err;
		}
		if (z->dstpos < z->dstlen) {
			return -1;
		}
		z->dstpos = z->dstlen = 0;

		if (z->status < TDEFL_STATUS_OKAY) {
			return z->status;
		}
	} while (z->status != TDEFL_STATUS_DONE);
	return 0;
}

/* Write 8-byte gzip trailer (CRC-32 then ISIZE). */
static int gzip_write_trailer(struct gzip_wstream *restrict z)
{
	unsigned char trailer[8];
	write_uint32_le(trailer + 0, z->crc);
	write_uint32_le(trailer + 4, z->isize);
	size_t n = sizeof(trailer);
	const int ret = stream_write(z->base, trailer, &n);
	if (ret == 0 && n < sizeof(trailer)) {
		return -1;
	}
	return ret;
}

/* Flush DEFLATE, write trailer, mark finished; base stream also flushed. Next write starts new member. */
static int gzip_flush(void *p)
{
	struct gzip_wstream *restrict z = p;
	if (z->finished) {
		return stream_flush(z->base);
	}
	int ret = gzip_flush_(z, TDEFL_FINISH);
	if (ret == 0) {
		ret = gzip_write_trailer(z);
	}
	if (ret == 0) {
		z->finished = true;
		z->crc = MZ_CRC32_INIT;
		z->isize = 0;
		ret = stream_flush(z->base);
	}
	return ret;
}

static int gzip_wclose(void *p)
{
	struct gzip_wstream *restrict z = p;
	int ret = 0;
	if (!z->finished) {
		ret = gzip_flush_(z, TDEFL_FINISH);
		if (ret == 0) {
			ret = gzip_write_trailer(z);
		}
	}
	const int err = stream_close(z->base);
	free(z);
	return ret != 0 ? ret : err;
}

struct stream *codec_gzip_writer(struct stream *base)
{
	if (base == NULL) {
		return NULL;
	}

	/* Write static 10-byte gzip header: ID1 ID2 CM FLG MTIME XFL OS */
	static const unsigned char header[10] = {
		0x1f, 0x8b, /* ID1, ID2 */
		0x08, /* CM: deflate */
		0x00, /* FLG: no optional fields */
		0,    0,    0, 0, /* MTIME: not set */
		0x00, /* XFL */
		0xff, /* OS: unknown */
	};
	size_t hlen = sizeof(header);
	const int herr = stream_write(base, header, &hlen);
	if (herr != 0 || hlen < sizeof(header)) {
		stream_close(base);
		return NULL;
	}

	struct gzip_wstream *z = malloc(sizeof(struct gzip_wstream));
	if (z == NULL) {
		LOGOOM();
		stream_close(base);
		return NULL;
	}

	static const struct stream_vftable vftable = {
		.write = gzip_write,
		.flush = gzip_flush,
		.close = gzip_wclose,
	};
	z->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->base = base;
	z->finished = false;
	z->status = TDEFL_STATUS_OKAY;

	const tdefl_status status =
		tdefl_init(&z->deflator, NULL, NULL, TDEFL_DEFAULT_MAX_PROBES);
	if (status != TDEFL_STATUS_OKAY) {
		stream_close(base);
		free(z);
		return NULL;
	}

	z->dstpos = z->dstlen = 0;
	z->crc = MZ_CRC32_INIT;
	z->isize = 0;
	return (struct stream *)z;
}

/* gzip header flag bits (RFC 1952) */
enum gzip_flags {
	/* File is probably ASCII text */
	GZIP_FTEXT = 1 << 0,
	/* Header CRC16 is present */
	GZIP_FHCRC = 1 << 1,
	/* Extra field is present */
	GZIP_FEXTRA = 1 << 2,
	/* Original filename is present */
	GZIP_FNAME = 1 << 3,
	/* File comment is present */
	GZIP_FCOMMENT = 1 << 4,
};

enum gzip_rstate {
	/* Parsing gzip member header */
	GZIP_R_HEADER,
	/* Decompressing DEFLATE body */
	GZIP_R_BODY,
	/* Consuming and validating 8-byte trailer */
	GZIP_R_TRAILER,
};

/* gzip header parser sub-phases */
enum gzip_hphase {
	/* Accumulating fixed 10-byte header */
	GZIP_HPHASE_HEADER,
	/* FEXTRA: reading 2-byte xlen (low) */
	GZIP_HPHASE_FEXTRA_1,
	/* FEXTRA: skipping xlen bytes */
	GZIP_HPHASE_FEXTRA_2,
	/* FNAME: skipping until NUL */
	GZIP_HPHASE_FNAME,
	/* FCOMMENT: skipping until NUL */
	GZIP_HPHASE_FCOMMENT,
	/* FHCRC: reading low byte */
	GZIP_HPHASE_FHCRC_1,
	/* FHCRC: reading high byte and validating */
	GZIP_HPHASE_FHCRC_2,
	/* Header parsing complete */
	GZIP_HPHASE_DONE,
	/* Special: waiting for second xlen byte */
	GZIP_HPHASE_XLEN_2 = 100,
};

/* inflate_stream fields plus a state machine that handles the header,
 * body and trailer of each member; supports multi-member streams */
struct gzip_rstream {
	struct stream s;
	struct stream *base;
	bool srceof : 1;
	int srcerr;
	size_t srclen;
	const unsigned char *srcbuf;
	/* DEFLATE decompressor state */
	tinfl_status status;
	tinfl_decompressor inflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[TINFL_LZ_DICT_SIZE];
	/* gzip state machine */
	enum gzip_rstate rstate;
	/* Accumulated read error (stored for return by gzip_rclose) */
	int rderr;
	/* Per-member output CRC-32 and uncompressed size */
	uint_least32_t crc;
	uint_least32_t isize;
	/* Trailer accumulator */
	unsigned char trail[8];
	size_t trailpos;
	/* Header parser state */
	unsigned char hdrbuf[10];
	size_t hdrpos;
	uint_least8_t hdrflg;
	uint_fast16_t xlen_remain;
	uint_least32_t hdrcrc;
	/* Header parser sub-phase (see enum gzip_hphase) */
	uint_fast8_t hphase;
};
ASSERT_SUPER(struct stream, struct gzip_rstream, s);

/* Parse gzip member header from z->srcbuf. Returns 1=done, 0=needs-more-input, -1=format-error. */
static int gzip_rstream_parse_hdr(struct gzip_rstream *restrict z)
{
	while (z->srclen > 0) {
		unsigned char b = *z->srcbuf;

		switch (z->hphase) {
		case GZIP_HPHASE_HEADER:
			z->hdrbuf[z->hdrpos] = b;
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			z->hdrpos++;
			if (z->hdrpos < 10) {
				break;
			}
			if (z->hdrbuf[0] != 0x1f || z->hdrbuf[1] != 0x8b ||
			    z->hdrbuf[2] != 0x08) {
				LOGD("gzip: invalid magic");
				return -1;
			}
			z->hdrflg = z->hdrbuf[3];
			/* Advance to first applicable optional-field phase */
			z->hphase = GZIP_HPHASE_FEXTRA_1;
			/* fallthrough */
		case GZIP_HPHASE_FEXTRA_1:
			if (!(z->hdrflg & GZIP_FEXTRA)) {
				z->hphase = GZIP_HPHASE_FNAME;
				break;
			}
			if (z->srclen < 2) {
				/* need both bytes before consuming */
				if (z->srclen == 0) {
					return 0;
				}
				/* only 1 byte available - stash and wait */
				z->hdrbuf[0] = b;
				z->hdrcrc = (uint_least32_t)mz_crc32(
					z->hdrcrc, z->srcbuf, 1);
				z->srcbuf++, z->srclen--;
				z->hphase = GZIP_HPHASE_XLEN_2;
				return 0;
			}
			z->xlen_remain =
				(uint_fast16_t)read_uint16_le(z->srcbuf);
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 2);
			z->srcbuf += 2, z->srclen -= 2;
			z->hphase = GZIP_HPHASE_FEXTRA_2;
			/* fallthrough */
		case GZIP_HPHASE_FEXTRA_2:
			if (z->xlen_remain > 0) {
				size_t skip = z->xlen_remain < z->srclen ?
						      z->xlen_remain :
						      z->srclen;
				z->hdrcrc = (uint_least32_t)mz_crc32(
					z->hdrcrc, z->srcbuf, skip);
				z->srcbuf += skip, z->srclen -= skip;
				z->xlen_remain -= (uint_fast16_t)skip;
				if (z->xlen_remain > 0) {
					return 0;
				}
			}
			z->hphase = GZIP_HPHASE_FNAME;
			/* fallthrough */
		case GZIP_HPHASE_FNAME:
			if (!(z->hdrflg & GZIP_FNAME)) {
				z->hphase = GZIP_HPHASE_FCOMMENT;
				break;
			}
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			if (b != 0x00) {
				/* still inside filename */
				return 0;
			}
			z->hphase = GZIP_HPHASE_FCOMMENT;
			break;
		case GZIP_HPHASE_FCOMMENT:
			if (!(z->hdrflg & GZIP_FCOMMENT)) {
				z->hphase = GZIP_HPHASE_FHCRC_1;
				break;
			}
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			if (b != 0x00) {
				return 0;
			}
			z->hphase = GZIP_HPHASE_FHCRC_1;
			break;
		case GZIP_HPHASE_FHCRC_1:
			if (!(z->hdrflg & GZIP_FHCRC)) {
				z->hphase = GZIP_HPHASE_DONE;
				return 1;
			}
			z->hdrbuf[0] = b;
			z->srcbuf++, z->srclen--;
			z->hphase = GZIP_HPHASE_FHCRC_2;
			return 0;
		case GZIP_HPHASE_FHCRC_2: {
			const uint_fast16_t stored =
				(uint_fast16_t)z->hdrbuf[0] |
				((uint_fast16_t)b << 8);
			const uint_fast16_t computed =
				(uint_fast16_t)(z->hdrcrc & 0xffffu);
			z->srcbuf++, z->srclen--;
			if (stored != computed) {
				LOGD("gzip: HCRC mismatch");
				return -1;
			}
		}
			z->hphase = GZIP_HPHASE_DONE;
			return 1;
		case GZIP_HPHASE_DONE:
			return 1;
		case GZIP_HPHASE_XLEN_2:
			z->xlen_remain = (uint_fast16_t)z->hdrbuf[0] |
					 ((uint_fast16_t)b << 8);
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			z->hphase = GZIP_HPHASE_FEXTRA_2;
			break;
		default:
			return -1;
		}
	}

	if (z->hphase == GZIP_HPHASE_DONE) {
		return 1;
	}
	/* Handle phases that don't consume bytes but need to advance */
	if (z->hphase == GZIP_HPHASE_FNAME && !(z->hdrflg & GZIP_FNAME)) {
		z->hphase = GZIP_HPHASE_FCOMMENT;
	}
	if (z->hphase == GZIP_HPHASE_FCOMMENT && !(z->hdrflg & GZIP_FCOMMENT)) {
		z->hphase = GZIP_HPHASE_FHCRC_1;
	}
	if (z->hphase == GZIP_HPHASE_FHCRC_1 && !(z->hdrflg & GZIP_FHCRC)) {
		return 1;
	}
	return 0;
}

static bool gzip_parse_header(struct gzip_rstream *z, size_t *len, int *ret)
{
	if (z->srclen == 0 && z->srceof) {
		/* Clean EOF between members */
		*len = 0;
		*ret = z->srcerr;
		return true;
	}
	const int hr = gzip_rstream_parse_hdr(z);
	if (hr < 0) {
		*len = 0;
		z->rderr = hr;
		*ret = hr;
		return true;
	}
	if (hr == 0) {
		if (z->srceof && z->srclen == 0) {
			/* Truncated header: no more input to complete it */
			*len = 0;
			z->rderr = -1;
			*ret = -1;
			return true;
		}
		/* The optional-field parser yields per byte; as long as input
		 * remains buffered (srclen > 0) it can still make progress,
		 * even after the base stream has signalled EOF. */
		return false;
	}
	/* Header complete - initialise DEFLATE decompressor */
	tinfl_init(&z->inflator);
	z->status = TINFL_STATUS_NEEDS_MORE_INPUT;
	z->crc = (uint_least32_t)MZ_CRC32_INIT;
	z->isize = 0;
	z->dstpos = z->dstlen = 0;
	z->rstate = GZIP_R_BODY;
	return false;
}

static bool gzip_decompress_body(
	struct gzip_rstream *z, const void **buf, size_t *len, int *ret)
{
	/* Wrap around sliding window when fully consumed */
	if (z->dstpos == z->dstlen && z->dstlen == sizeof(z->dstbuf)) {
		z->dstpos = z->dstlen = 0;
	}

	if (z->srclen > 0 && z->dstlen < sizeof(z->dstbuf) &&
	    z->status > TINFL_STATUS_DONE) {
		const unsigned char *src = z->srcbuf;
		size_t srclen = z->srclen;
		unsigned char *dst = z->dstbuf + z->dstlen;
		size_t dstlen = sizeof(z->dstbuf) - z->dstlen;
		/* raw DEFLATE */
		int flags = 0;
		if (!z->srceof) {
			flags |= TINFL_FLAG_HAS_MORE_INPUT;
		}
		z->status = tinfl_decompress(
			&z->inflator, src, &srclen, z->dstbuf, dst, &dstlen,
			flags);
		z->srcbuf += srclen;
		z->srclen -= srclen;
		z->dstlen += dstlen;
	}

	if (z->dstpos < z->dstlen) {
		const size_t maxread = *len;
		size_t n = z->dstlen - z->dstpos;
		if (n > maxread) {
			n = maxread;
		}
		z->crc = (uint_least32_t)mz_crc32(
			z->crc, z->dstbuf + z->dstpos, n);
		z->isize += (uint_least32_t)n;
		*buf = z->dstbuf + z->dstpos;
		*len = n;
		z->dstpos += n;
		if (z->dstpos == z->dstlen && z->status == TINFL_STATUS_DONE) {
			z->rstate = GZIP_R_TRAILER;
			z->trailpos = 0;
		}
		*ret = 0;
		return true;
	}

	if (z->status == TINFL_STATUS_DONE) {
		z->rstate = GZIP_R_TRAILER;
		z->trailpos = 0;
		return false;
	}

	if (z->status < TINFL_STATUS_DONE) {
		*len = 0;
		z->rderr = z->status;
		*ret = z->status;
		return true;
	}

	if (z->srceof) {
		/* Unexpected EOF inside DEFLATE stream */
		*len = 0;
		z->rderr = -1;
		*ret = -1;
		return true;
	}
	return false;
}

static bool gzip_validate_trailer(struct gzip_rstream *z, size_t *len, int *ret)
{
	while (z->trailpos < 8 && z->srclen > 0) {
		z->trail[z->trailpos++] = *z->srcbuf;
		z->srcbuf++, z->srclen--;
	}
	if (z->trailpos < 8) {
		if (z->srceof) {
			LOGD("gzip: short trailer");
			*len = 0;
			z->rderr = -1;
			*ret = -1;
			return true;
		}
		return false;
	}
	const uint_least32_t stored_crc =
		(uint_least32_t)read_uint32_le(z->trail);
	if (stored_crc != z->crc) {
		LOGD("gzip: CRC mismatch");
		*len = 0;
		z->rderr = -1;
		*ret = -1;
		return true;
	}
	const uint_least32_t stored_isize =
		(uint_least32_t)read_uint32_le(z->trail + 4);
	if (stored_isize != z->isize) {
		LOGD("gzip: ISIZE mismatch");
		*len = 0;
		z->rderr = -1;
		*ret = -1;
		return true;
	}
	/* Check for more members */
	if (z->srclen == 0 && z->srceof) {
		*len = 0;
		*ret = z->srcerr;
		return true;
	}
	/* Reset header parser for next member */
	z->hdrpos = 0;
	z->hphase = GZIP_HPHASE_HEADER;
	z->hdrcrc = (uint_least32_t)MZ_CRC32_INIT;
	z->rstate = GZIP_R_HEADER;
	return false;
}

static int gzip_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct gzip_rstream *restrict z = p;
	for (;;) {
		if (z->srclen == 0 && !z->srceof) {
			const void *srcbuf;
			size_t n = IO_BUFSIZE;
			z->srcerr = stream_direct_read(z->base, &srcbuf, &n);
			if (n < IO_BUFSIZE || z->srcerr != 0) {
				z->srceof = true;
			}
			z->srclen = n;
			z->srcbuf = srcbuf;
		}

		int ret;
		bool done;
		switch (z->rstate) {
		case GZIP_R_HEADER:
			done = gzip_parse_header(z, len, &ret);
			break;
		case GZIP_R_BODY:
			done = gzip_decompress_body(z, buf, len, &ret);
			break;
		case GZIP_R_TRAILER:
			done = gzip_validate_trailer(z, len, &ret);
			break;
		}
		if (done) {
			return ret;
		}
	}
}

static int gzip_rclose(void *p)
{
	struct gzip_rstream *restrict z = p;
	const int rderr = z->rderr;
	const int err = stream_close(z->base);
	free(z);
	return rderr != 0 ? rderr : err;
}

struct stream *codec_gzip_reader(struct stream *base)
{
	if (base == NULL) {
		return NULL;
	}

	if (base->vftable->direct_read == NULL) {
		base = io_bufreader(base, IO_BUFSIZE);
		if (base == NULL) {
			return NULL;
		}
	}

	struct gzip_rstream *z = malloc(sizeof(struct gzip_rstream));
	if (z == NULL) {
		LOGOOM();
		stream_close(base);
		return NULL;
	}

	static const struct stream_vftable vftable = {
		.direct_read = gzip_direct_read,
		.close = gzip_rclose,
	};
	z->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->base = base;
	z->srceof = false;
	z->srcerr = 0;
	z->srclen = 0;
	z->rstate = GZIP_R_HEADER;
	z->rderr = 0;
	z->crc = (uint_least32_t)MZ_CRC32_INIT;
	z->isize = 0;
	z->trailpos = 0;
	z->hdrpos = 0;
	z->hphase = GZIP_HPHASE_HEADER;
	z->hdrcrc = (uint_least32_t)MZ_CRC32_INIT;
	z->dstpos = z->dstlen = 0;
	return (struct stream *)z;
}

/* codec_lua_reader: auto-detect gzip, skip BOM and shebang */

enum lua_rstate {
	LUA_SKIP_BOM,
	LUA_SKIP_SHEBANG,
	LUA_PASSTHROUGH,
};

struct lua_rstream {
	struct stream s;
	struct stream *inner;
	enum lua_rstate state;
	int rderr;
};
ASSERT_SUPER(struct stream, struct lua_rstream, s);

/* Skip UTF-8 BOM if present; transition to LUA_SKIP_SHEBANG. Returns false for non-UTF-8 BOM. */
static bool lua_skip_bom(
	struct lua_rstream *z, const unsigned char *p, size_t n, size_t *offset)
{
	if (n >= 4 && p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE &&
	    p[3] == 0xFF) {
		LOGD("lua: unsupported BOM (UTF-32 BE)");
		z->rderr = -1;
		return false;
	}
	if (n >= 4 && p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 &&
	    p[3] == 0x00) {
		LOGD("lua: unsupported BOM (UTF-32 LE)");
		z->rderr = -1;
		return false;
	}
	if (n >= 2 && p[0] == 0xFE && p[1] == 0xFF) {
		LOGD("lua: unsupported BOM (UTF-16 BE)");
		z->rderr = -1;
		return false;
	}
	if (n >= 2 && p[0] == 0xFF && p[1] == 0xFE) {
		LOGD("lua: unsupported BOM (UTF-16 LE)");
		z->rderr = -1;
		return false;
	}
	/* UTF-8 BOM: skip EF BB BF */
	if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
		*offset = 3;
	}
	z->state = LUA_SKIP_SHEBANG;
	return true;
}

/* Skip shebang from p[*offset]; transition to LUA_PASSTHROUGH.
 * State stays LUA_SKIP_SHEBANG if no newline in chunk — caller retries. */
static void lua_skip_shebang(
	struct lua_rstream *z, const unsigned char *p, size_t n, size_t *offset)
{
	if (n - *offset < 2 || p[*offset] != '#' || p[*offset + 1] != '!') {
		z->state = LUA_PASSTHROUGH;
		return;
	}
	for (size_t i = *offset + 2; i < n; i++) {
		if (p[i] == '\n') {
			*offset = i + 1;
			z->state = LUA_PASSTHROUGH;
			return;
		}
	}
}

static int lua_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct lua_rstream *restrict z = p;

	if (z->state == LUA_PASSTHROUGH) {
		int err = stream_direct_read(z->inner, buf, len);
		if (err != 0) {
			z->rderr = err;
		}
		return err;
	}

	for (;;) {
		const void *data;
		size_t n = (z->state == LUA_SKIP_BOM) ? 4 : *len;
		const int err = stream_direct_read(z->inner, &data, &n);

		if (err != 0) {
			z->state = LUA_PASSTHROUGH;
			z->rderr = err;
			*len = 0;
			return err;
		}
		if (n == 0) {
			z->state = LUA_PASSTHROUGH;
			*len = 0;
			return 0;
		}

		const unsigned char *p = data;
		size_t offset = 0;

		if (z->state == LUA_SKIP_BOM) {
			if (!lua_skip_bom(z, p, n, &offset)) {
				*len = 0;
				return -1;
			}
		}
		if (z->state == LUA_SKIP_SHEBANG) {
			lua_skip_shebang(z, p, n, &offset);
		}

		if (offset < n) {
			*buf = p + offset;
			*len = n - offset;
			return 0;
		}
	}
}

static int lua_close(void *p)
{
	struct lua_rstream *restrict z = p;
	const int rderr = z->rderr;
	const int err = stream_close(z->inner);
	free(z);
	return rderr != 0 ? rderr : err;
}

static struct stream *lua_reader_new(struct stream *base)
{
	if (base == NULL) {
		return NULL;
	}

	/* Wrap with bufreader so we can peek for gzip magic */
	if (base->vftable->direct_read == NULL) {
		base = io_bufreader(base, IO_BUFSIZE);
		if (base == NULL) {
			return NULL;
		}
	}

	struct stream *inner;
	{
		const void *peek;
		size_t peek_len = 2;
		const int err = io_bufpeek(base, &peek, &peek_len);
		if (err == 0 && peek_len >= 2 &&
		    *(const unsigned char *)peek == 0x1f &&
		    *((const unsigned char *)peek + 1) == 0x8b) {
			inner = codec_gzip_reader(base);
			if (inner == NULL) {
				return NULL;
			}
		} else {
			inner = base;
		}
	}

	struct lua_rstream *z = malloc(sizeof(struct lua_rstream));
	if (z == NULL) {
		LOGOOM();
		stream_close(inner);
		return NULL;
	}

	static const struct stream_vftable vftable = {
		.direct_read = lua_direct_read,
		.close = lua_close,
	};
	z->s = (struct stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->inner = inner;
	z->state = LUA_SKIP_BOM;
	z->rderr = 0;
	return (struct stream *)z;
}

struct stream *codec_lua_reader(const char *path)
{
	FILE *f;
	if (strcmp(path, "-") == 0) {
		f = stdin;
	} else {
		f = fopen(path, "r");
		if (f == NULL) {
			LOGE_F("codec_lua_reader: fopen(\"%s\"): (%d) %s", path,
			       errno, strerror(errno));
			return NULL;
		}
	}
	struct stream *s = io_filereader(f);
	if (s == NULL) {
		LOGOOM();
		if (f != stdin) {
			(void)fclose(f);
		}
		return NULL;
	}
	s = lua_reader_new(s);
	if (s == NULL) {
		return NULL;
	}
	return s;
}
