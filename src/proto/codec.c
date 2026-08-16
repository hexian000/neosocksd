/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "codec.h"

#include "binary/serialize.h"
#include "io/file.h"
#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "meta/class.h"
#include "miniz.h"
#include "utils/slog.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct deflate_stream {
	struct io_stream s;
	struct io_stream *base;
	tdefl_status status;
	tdefl_compressor deflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[IO_BUFSIZE];
};
ASSERT_SUPER(struct io_stream, struct deflate_stream, s);

static int
deflate_write(void *p, const void *restrict buf, size_t *restrict len)
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
		const int err = io_stream_write(z->base, avail, &n);
		z->dstpos += n;
		if (err != 0) {
			*len = nwritten;
			return err;
		}
		if (z->dstpos < z->dstlen) {
			*len = nwritten;
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
	for (;;) {
		unsigned char *buf = z->dstbuf + z->dstlen;
		const size_t avail = sizeof(z->dstbuf) - z->dstlen;
		size_t n = avail;
		z->status = tdefl_compress(
			&z->deflator, NULL, NULL, buf, &n, flush);
		z->dstlen += n;

		buf = z->dstbuf + z->dstpos;
		size_t w = z->dstlen - z->dstpos;
		const int err = io_stream_write(z->base, buf, &w);
		z->dstpos += w;
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
		/* TDEFL_FINISH reaches DONE; TDEFL_FULL_FLUSH never does (it
		 * re-emits an empty sync marker each call), so also stop once a
		 * call no longer fills the output buffer -- i.e. all pending
		 * output plus the flush marker has been emitted. */
		if (z->status == TDEFL_STATUS_DONE || n < avail) {
			break;
		}
	}
	return 0;
}

/* full flush: emit a sync point so the decompressor can restart here */
static int deflate_flush(void *p)
{
	struct deflate_stream *restrict z = p;
	int ret = deflate_flush_(z, TDEFL_FULL_FLUSH);
	if (ret == 0) {
		ret = io_stream_flush(z->base);
	}
	return ret;
}

static int deflate_close(void *p)
{
	struct deflate_stream *restrict z = p;
	const int flusherr = deflate_flush_(z, TDEFL_FINISH);
	const int err = io_stream_close(z->base);
	free(z);
	return flusherr != 0 ? flusherr : err;
}

static struct io_stream *deflate_writer(struct io_stream *base, const bool zlib)
{
	if (base == NULL) {
		return NULL;
	}

	struct deflate_stream *z = malloc(sizeof(struct deflate_stream));
	if (z == NULL) {
		LOGOOM();
		io_stream_close(base);
		return NULL;
	}

	static const struct io_stream_vftable vftable = {
		.write = deflate_write,
		.flush = deflate_flush,
		.close = deflate_close,
	};
	z->s = (struct io_stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->base = base;
	z->status = TDEFL_STATUS_OKAY;

	const int flags =
		(zlib ? TDEFL_WRITE_ZLIB_HEADER : 0) | TDEFL_DEFAULT_MAX_PROBES;
	const tdefl_status status = tdefl_init(&z->deflator, NULL, NULL, flags);
	if (status != TDEFL_STATUS_OKAY) {
		io_stream_close(base);
		free(z);
		return NULL;
	}

	z->dstpos = z->dstlen = 0;
	return (struct io_stream *)z;
}

struct io_stream *codec_zlib_writer(struct io_stream *base)
{
	return deflate_writer(base, true);
}

struct io_stream *codec_deflate_writer(struct io_stream *base)
{
	return deflate_writer(base, false);
}

/* Cap on total decompressed output per stream. Decompression is an unbounded
 * amplification vector -- a small compressed input can expand to gigabytes --
 * and the daemon is single-threaded, so an uncapped inflate/gunzip lets one
 * request stall every session. Once a stream's cumulative output exceeds this
 * bound it aborts with a decode error rather than exhausting memory/CPU.
 * Overridable at build time so the unit test can drive the abort at a small
 * size instead of producing gigabytes. */
#ifndef CODEC_MAX_INFLATE
#define CODEC_MAX_INFLATE (2ull << 30) /* 2 GiB */
#endif

struct inflate_stream {
	struct io_stream s;
	struct io_stream *base;
	bool srceof : 1;
	int srcerr;
	size_t srclen;
	const unsigned char *srcbuf;
	int flags;
	tinfl_status status;
	tinfl_decompressor inflator;
	size_t dstpos, dstlen;
	size_t outtotal;
	unsigned char dstbuf[TINFL_LZ_DICT_SIZE];
};
ASSERT_SUPER(struct io_stream, struct inflate_stream, s);

static int
inflate_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct inflate_stream *restrict z = p;
	do {
		if (z->srclen == 0 && !z->srceof) {
			const void *srcbuf;
			size_t n = IO_BUFSIZE;
			z->srcerr = io_stream_direct_read(z->base, &srcbuf, &n);
			/* io_stream_direct_read may return a short read that is not
			 * EOF (io/stream.h: "any output length > 0 should be
			 * considered normal"); only n == 0 (or an error) is EOF.
			 * Treating a short read as EOF would drop
			 * TINFL_FLAG_HAS_MORE_INPUT and mis-decode valid input. */
			if (n == 0 || z->srcerr != 0) {
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
			z->outtotal += dstlen;
			if (z->outtotal > CODEC_MAX_INFLATE) {
				/* decompression bomb: cumulative output exceeds
				 * the cap. Remote-triggerable, so log at DEBUG. */
				LOGD_F("inflate: output exceeds %zu-byte limit, aborting",
				       (size_t)CODEC_MAX_INFLATE);
				z->status = TINFL_STATUS_FAILED;
				*len = 0;
				return z->status;
			}
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
			/* Defer a base read error until all buffered input has
			 * been decoded: the base may return data and an error
			 * together, and srclen>0 still holds decodable bytes.
			 * Mirrors gzip_decompress_body. */
			if (z->dstpos == z->dstlen && z->srclen == 0) {
				return z->srcerr;
			}
			return 0;
		}
	} while (z->status > TINFL_STATUS_DONE && !z->srceof);

	*len = 0;
	/* Surface the base's error code rather than the inflate status when the
	 * input ended on a base error (e.g. a first refill that returned an
	 * error with n == 0), otherwise the original code would be lost. */
	if (z->srcerr != 0) {
		return z->srcerr;
	}
	if (z->status != TINFL_STATUS_DONE) {
		return z->status;
	}
	return 0;
}

static int inflate_close(void *p)
{
	struct inflate_stream *restrict z = p;
	/* surface a decode error (e.g. an adler-32 mismatch) even when the
	 * caller closed without a final read to EOF, mirroring gzip_rclose */
	const int rderr = (z->status < TINFL_STATUS_DONE) ? (int)z->status : 0;
	const int err = io_stream_close(z->base);
	free(z);
	return rderr != 0 ? rderr : err;
}

static struct io_stream *inflate_reader(struct io_stream *base, const bool zlib)
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
		io_stream_close(base);
		return NULL;
	}

	static const struct io_stream_vftable vftable = {
		.direct_read = inflate_direct_read,
		.close = inflate_close,
	};
	z->s = (struct io_stream){
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
	z->outtotal = 0;
	return (struct io_stream *)z;
}

struct io_stream *codec_zlib_reader(struct io_stream *base)
{
	return inflate_reader(base, true);
}

struct io_stream *codec_inflate_reader(struct io_stream *base)
{
	return inflate_reader(base, false);
}

/* RFC 1952 - gzip format implementation */

/* Resumable phase of a member-finish (TDEFL_FINISH drain, then trailer).
 * Tracked so a partial write on either sub-step resumes at the right place
 * rather than re-running the whole finish (which would re-enter tdefl_compress
 * after DONE -- a BAD_PARAM wedge -- or rewrite the trailer prefix). */
enum gzip_wphase {
	GZIP_W_BODY, /* not finishing: normal writes */
	GZIP_W_FINISH, /* draining the TDEFL_FINISH deflate output */
	GZIP_W_TRAILER, /* draining the staged 8-byte trailer */
};

/* same as deflate_stream, extended with running CRC-32 and
 * uncompressed byte count for the gzip trailer */
struct gzip_wstream {
	struct io_stream s;
	struct io_stream *base;
	bool finished : 1;
	enum gzip_wphase wphase;
	tdefl_status status;
	tdefl_compressor deflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[IO_BUFSIZE];
	/* gzip trailer state */
	uint_least32_t crc;
	uint_least32_t isize;
};
ASSERT_SUPER(struct io_stream, struct gzip_wstream, s);

static int gzip_write(void *p, const void *restrict buf, size_t *restrict len)
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
		/* Stage the header once, then drain it resumably (like the body
		 * path below) so a partial write is resumed from where it stopped
		 * rather than re-emitted whole on retry, which would corrupt the
		 * member. dstbuf/dstpos/dstlen are idle here (the prior member
		 * finished and reset them). */
		if (z->dstlen == 0) {
			memcpy(z->dstbuf, header, sizeof(header));
			z->dstpos = 0;
			z->dstlen = sizeof(header);
		}
		size_t hlen = z->dstlen - z->dstpos;
		const int herr =
			io_stream_write(z->base, z->dstbuf + z->dstpos, &hlen);
		z->dstpos += hlen;
		if (herr != 0) {
			*len = 0;
			return herr;
		}
		if (z->dstpos < z->dstlen) {
			*len = 0;
			return -1;
		}
		z->dstpos = z->dstlen = 0;
		const tdefl_status status = tdefl_init(
			&z->deflator, NULL, NULL, TDEFL_DEFAULT_MAX_PROBES);
		if (status != TDEFL_STATUS_OKAY) {
			*len = 0;
			return status;
		}
		z->status = TDEFL_STATUS_OKAY;
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
		const int err = io_stream_write(z->base, avail, &n);
		z->dstpos += n;
		if (err != 0) {
			*len = nwritten;
			return err;
		}
		if (z->dstpos < z->dstlen) {
			*len = nwritten;
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
		/* Once the compressor has returned DONE, calling tdefl_compress
		 * again returns TDEFL_STATUS_BAD_PARAM; on a resumed finish only
		 * the staged output still needs draining, so skip recompression
		 * and just drain the remaining dstbuf. */
		if (z->status != TDEFL_STATUS_DONE) {
			unsigned char *buf = z->dstbuf + z->dstlen;
			size_t n = sizeof(z->dstbuf) - z->dstlen;
			z->status = tdefl_compress(
				&z->deflator, NULL, NULL, buf, &n, flush);
			z->dstlen += n;
		}

		unsigned char *buf = z->dstbuf + z->dstpos;
		size_t n = z->dstlen - z->dstpos;
		const int err = io_stream_write(z->base, buf, &n);
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

/* Finish the current member resumably: drain the TDEFL_FINISH deflate output,
 * then the 8-byte trailer (CRC-32 then ISIZE). A partial write on either
 * sub-step returns nonzero and, on retry, resumes at the phase recorded in
 * z->wphase rather than re-running the finish. Leaves z->wphase == GZIP_W_BODY
 * and dstbuf empty on success. */
static int gzip_finish(struct gzip_wstream *restrict z)
{
	if (z->wphase == GZIP_W_BODY) {
		z->wphase = GZIP_W_FINISH;
	}
	if (z->wphase == GZIP_W_FINISH) {
		const int ret = gzip_flush_(z, TDEFL_FINISH);
		if (ret != 0) {
			return ret;
		}
		/* deflate output fully drained (dstbuf idle); stage the trailer
		 * and drain it the same resumable way */
		write_uint32_le(z->dstbuf + 0, z->crc);
		write_uint32_le(z->dstbuf + 4, z->isize);
		z->dstpos = 0;
		z->dstlen = 8;
		z->wphase = GZIP_W_TRAILER;
	}
	size_t n = z->dstlen - z->dstpos;
	const int err = io_stream_write(z->base, z->dstbuf + z->dstpos, &n);
	z->dstpos += n;
	if (err != 0) {
		return err;
	}
	if (z->dstpos < z->dstlen) {
		return -1;
	}
	z->dstpos = z->dstlen = 0;
	z->wphase = GZIP_W_BODY;
	return 0;
}

/* Flush DEFLATE, write trailer, mark finished; base stream also flushed. Next write starts new member. */
static int gzip_flush(void *p)
{
	struct gzip_wstream *restrict z = p;
	if (z->finished) {
		return io_stream_flush(z->base);
	}
	const int ret = gzip_finish(z);
	if (ret != 0) {
		return ret;
	}
	/* The member (deflate output + trailer) is fully written; mark it
	 * finished before flushing the base so a base-flush failure retries
	 * only the flush, not the already-emitted trailer. */
	z->finished = true;
	z->crc = MZ_CRC32_INIT;
	z->isize = 0;
	return io_stream_flush(z->base);
}

static int gzip_wclose(void *p)
{
	struct gzip_wstream *restrict z = p;
	int ret = 0;
	if (!z->finished) {
		ret = gzip_finish(z);
	}
	const int err = io_stream_close(z->base);
	free(z);
	return ret != 0 ? ret : err;
}

struct io_stream *codec_gzip_writer(struct io_stream *base)
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
	const int herr = io_stream_write(base, header, &hlen);
	if (herr != 0 || hlen < sizeof(header)) {
		io_stream_close(base);
		return NULL;
	}

	struct gzip_wstream *z = malloc(sizeof(struct gzip_wstream));
	if (z == NULL) {
		LOGOOM();
		io_stream_close(base);
		return NULL;
	}

	static const struct io_stream_vftable vftable = {
		.write = gzip_write,
		.flush = gzip_flush,
		.close = gzip_wclose,
	};
	z->s = (struct io_stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->base = base;
	z->finished = false;
	z->wphase = GZIP_W_BODY;
	z->status = TDEFL_STATUS_OKAY;

	const tdefl_status status =
		tdefl_init(&z->deflator, NULL, NULL, TDEFL_DEFAULT_MAX_PROBES);
	if (status != TDEFL_STATUS_OKAY) {
		io_stream_close(base);
		free(z);
		return NULL;
	}

	z->dstpos = z->dstlen = 0;
	z->crc = MZ_CRC32_INIT;
	z->isize = 0;
	return (struct io_stream *)z;
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
	/* Bits 5-7 are reserved and must be zero */
	GZIP_FRESERVED = 0xe0,
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
	struct io_stream s;
	struct io_stream *base;
	bool srceof : 1;
	int srcerr;
	size_t srclen;
	const unsigned char *srcbuf;
	/* DEFLATE decompressor state */
	tinfl_status status;
	tinfl_decompressor inflator;
	size_t dstpos, dstlen;
	size_t outtotal;
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
	uint_least16_t xlen_remain;
	uint_least32_t hdrcrc;
	/* Header parser sub-phase (see enum gzip_hphase) */
	uint_least8_t hphase;
};
ASSERT_SUPER(struct io_stream, struct gzip_rstream, s);

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
			if (z->hdrflg & GZIP_FRESERVED) {
				/* RFC 1952: reserved FLG bits must be zero */
				LOGD("gzip: reserved header flag bits set");
				return -1;
			}
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
				/* only 1 byte available - stash and wait. Read
				 * from srcbuf directly: b is the once-per-loop
				 * byte and is stale here after the HEADER phase
				 * fell through and advanced srcbuf. */
				z->hdrbuf[0] = *z->srcbuf;
				z->hdrcrc = (uint_least32_t)mz_crc32(
					z->hdrcrc, z->srcbuf, 1);
				z->srcbuf++, z->srclen--;
				z->hphase = GZIP_HPHASE_XLEN_2;
				return 0;
			}
			z->xlen_remain =
				(uint_least16_t)read_uint16_le(z->srcbuf);
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
				z->xlen_remain -= (uint_least16_t)skip;
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
			if (z->srclen == 0) {
				/* FEXTRA_2 falls through here without re-checking the
				 * loop guard; the buffer may be exhausted exactly at
				 * the FEXTRA boundary, so wait for more input before
				 * reading the name byte */
				return 0;
			}
			{
				/* read the terminator byte from srcbuf directly:
				 * b is stale when FEXTRA_2 fell through here */
				const unsigned char c = *z->srcbuf;
				z->hdrcrc = (uint_least32_t)mz_crc32(
					z->hdrcrc, z->srcbuf, 1);
				z->srcbuf++, z->srclen--;
				if (c != 0x00) {
					/* still inside filename */
					return 0;
				}
			}
			z->hphase = GZIP_HPHASE_FCOMMENT;
			break;
		case GZIP_HPHASE_FCOMMENT:
			if (!(z->hdrflg & GZIP_FCOMMENT)) {
				z->hphase = GZIP_HPHASE_FHCRC_1;
				break;
			}
			{
				const unsigned char c = *z->srcbuf;
				z->hdrcrc = (uint_least32_t)mz_crc32(
					z->hdrcrc, z->srcbuf, 1);
				z->srcbuf++, z->srclen--;
				if (c != 0x00) {
					return 0;
				}
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
			z->xlen_remain =
				(uint_least16_t)((uint_fast16_t)z->hdrbuf[0] |
						 ((uint_fast16_t)b << 8));
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

static bool gzip_parse_header(
	struct gzip_rstream *restrict z, size_t *restrict len,
	int *restrict ret)
{
	if (z->srclen == 0 && z->srceof) {
		if (z->hphase == GZIP_HPHASE_HEADER && z->hdrpos == 0) {
			/* Clean EOF at a member boundary (end of stream, or an
			 * empty stream): nothing of a new member has been read. */
			*len = 0;
			*ret = z->srcerr;
			return true;
		}
		/* EOF partway through a member header. Now that a short read is
		 * no longer treated as EOF, this check also fires when the base
		 * signals EOF on a refill after a partial header was buffered, so
		 * it must distinguish a member boundary (above) from a truncated
		 * header (here) rather than silently accepting the truncation. */
		*len = 0;
		z->rderr = -1;
		*ret = -1;
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
	struct gzip_rstream *restrict z, const void **restrict buf,
	size_t *restrict len, int *restrict ret)
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
		z->outtotal += dstlen;
		if (z->outtotal > CODEC_MAX_INFLATE) {
			/* decompression bomb: cumulative output (summed across
			 * gzip members) exceeds the cap. Remote-triggerable, so
			 * log at DEBUG. */
			LOGD_F("gzip: output exceeds %zu-byte limit, aborting",
			       (size_t)CODEC_MAX_INFLATE);
			z->status = TINFL_STATUS_FAILED;
			z->rderr = z->status;
			*len = 0;
			*ret = z->status;
			return true;
		}
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

static bool gzip_validate_trailer(
	struct gzip_rstream *restrict z, size_t *restrict len,
	int *restrict ret)
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

static int
gzip_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct gzip_rstream *restrict z = p;
	for (;;) {
		if (z->srclen == 0 && !z->srceof) {
			const void *srcbuf;
			size_t n = IO_BUFSIZE;
			z->srcerr = io_stream_direct_read(z->base, &srcbuf, &n);
			/* a short read is not EOF (see inflate_direct_read); only
			 * n == 0 (or an error) ends the input */
			if (n == 0 || z->srcerr != 0) {
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
		default:
			/* unreachable: rstate only holds the three states above;
			 * return an error rather than read done/ret uninitialized */
			return -1;
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
	const int err = io_stream_close(z->base);
	free(z);
	return rderr != 0 ? rderr : err;
}

struct io_stream *codec_gzip_reader(struct io_stream *base)
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
		io_stream_close(base);
		return NULL;
	}

	static const struct io_stream_vftable vftable = {
		.direct_read = gzip_direct_read,
		.close = gzip_rclose,
	};
	z->s = (struct io_stream){
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
	z->outtotal = 0;
	return (struct io_stream *)z;
}

/* codec_lua_reader: auto-detect gzip, skip BOM and shebang */

enum lua_rstate {
	LUA_SKIP_BOM,
	LUA_SKIP_SHEBANG,
	LUA_PASSTHROUGH,
};

/* Initial peek size: enough to see the longest BOM (4 bytes, UTF-32) and
 * the 2-byte "#!" shebang prefix that may immediately follow it in the
 * same read. */
#define LUA_PEEK_SIZE 8

struct lua_rstream {
	struct io_stream s;
	struct io_stream *inner;
	enum lua_rstate state;
	bool shebang_confirmed;
	int rderr;
	/* Prefix window: the first read is copied here (via io_stream_read, which
	 * fills up to LUA_PEEK_SIZE) so BOM/shebang detection cannot be defeated
	 * by a short read splitting the prefix across calls; any post-prefix
	 * bytes are handed out from peekbuf[peekpos..peeklen). */
	size_t peeklen;
	size_t peekpos;
	unsigned char peekbuf[LUA_PEEK_SIZE];
};
ASSERT_SUPER(struct io_stream, struct lua_rstream, s);

/* Skip UTF-8 BOM if present; transition to LUA_SKIP_SHEBANG. Returns false for non-UTF-8 BOM. */
static bool lua_skip_bom(
	struct lua_rstream *restrict z, const unsigned char *restrict p,
	size_t n, size_t *restrict offset)
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

/* Skip shebang from p[*offset]; transition to LUA_PASSTHROUGH once the
 * terminating newline is found. If no newline appears in this chunk,
 * *offset is advanced to n (the whole chunk was shebang content) and the
 * state stays LUA_SKIP_SHEBANG for the caller to retry with more data;
 * the "#!" prefix is only ever checked once (shebang_confirmed latches
 * it), since a retry's chunk starts mid-line, not at "#!" again. */
static void lua_skip_shebang(
	struct lua_rstream *restrict z, const unsigned char *restrict p,
	size_t n, size_t *restrict offset)
{
	if (!z->shebang_confirmed) {
		if (n - *offset < 2 || p[*offset] != '#' ||
		    p[*offset + 1] != '!') {
			z->state = LUA_PASSTHROUGH;
			return;
		}
		z->shebang_confirmed = true;
		*offset += 2;
	}
	for (size_t i = *offset; i < n; i++) {
		if (p[i] == '\n') {
			*offset = i + 1;
			z->state = LUA_PASSTHROUGH;
			return;
		}
	}
	*offset = n;
}

/* Hand out the next slice of the peek window, capped by the caller's request. */
static int lua_serve_peek(
	struct lua_rstream *restrict z, const void **restrict buf,
	size_t *restrict len)
{
	const size_t avail = z->peeklen - z->peekpos;
	const size_t n = (*len < avail) ? *len : avail;
	*buf = z->peekbuf + z->peekpos;
	*len = n;
	z->peekpos += n;
	return 0;
}

static int
lua_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct lua_rstream *restrict z = p;

	/* A latched read error is sticky, including an unsupported-BOM
	 * rejection: once set, every subsequent read returns it rather than
	 * serving the rejected prefix or refilling from mid-file. */
	if (z->rderr != 0) {
		*len = 0;
		return z->rderr;
	}

	/* Serve any post-prefix bytes still buffered in the peek window. */
	if (z->peekpos < z->peeklen) {
		return lua_serve_peek(z, buf, len);
	}

	if (z->state == LUA_SKIP_BOM) {
		/* Fill the peek window with a copying read rather than a single
		 * direct read: a direct read may legitimately return fewer bytes
		 * than requested (its contract only promises "> 0"), which could
		 * split a multi-byte BOM or the "#!" prefix across reads and
		 * defeat detection. io_stream_read loops the underlying reader and
		 * only comes up short at EOF, so the window holds the whole
		 * prefix whenever the source has that many bytes. */
		z->peeklen = LUA_PEEK_SIZE;
		z->peekpos = 0;
		const int err =
			io_stream_read(z->inner, z->peekbuf, &z->peeklen);
		if (err != 0) {
			z->state = LUA_PASSTHROUGH;
			z->rderr = err;
			*len = 0;
			return err;
		}
		if (z->peeklen == 0) {
			z->state = LUA_PASSTHROUGH;
			*len = 0;
			return 0;
		}
		size_t offset = 0;
		if (!lua_skip_bom(z, z->peekbuf, z->peeklen, &offset)) {
			/* discard the rejected prefix so it is never served; the
			 * error latched in z->rderr makes this terminal (checked
			 * at the top on any subsequent read) */
			z->peekpos = z->peeklen;
			*len = 0;
			return z->rderr;
		}
		/* Skip the shebang if its start is within the window. If the line
		 * runs past the window the state stays LUA_SKIP_SHEBANG and the
		 * remainder is scanned directly from the inner stream below. */
		lua_skip_shebang(z, z->peekbuf, z->peeklen, &offset);
		z->peekpos = offset;
		if (z->peekpos < z->peeklen) {
			return lua_serve_peek(z, buf, len);
		}
	}

	if (z->state == LUA_PASSTHROUGH) {
		const int err = io_stream_direct_read(z->inner, buf, len);
		if (err != 0) {
			z->rderr = err;
		}
		return err;
	}

	/* LUA_SKIP_SHEBANG continuing beyond the peek window: scan the inner
	 * stream directly for the terminating newline, discarding shebang
	 * content, then hand back the first real source bytes. */
	for (;;) {
		const void *data;
		size_t n = *len;
		const int err = io_stream_direct_read(z->inner, &data, &n);
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
		const unsigned char *q = data;
		size_t offset = 0;
		/* Only scan while still skipping the shebang: once its newline is
		 * found the state flips to LUA_PASSTHROUGH, and if that newline was
		 * the last byte of a chunk (offset == n) the loop re-iterates over
		 * the next chunk of real source, which must be passed through, not
		 * re-stripped. */
		if (z->state == LUA_SKIP_SHEBANG) {
			lua_skip_shebang(z, q, n, &offset);
			if (z->state == LUA_SKIP_SHEBANG) {
				/* whole chunk was shebang content; read more */
				continue;
			}
		}
		if (offset < n) {
			*buf = q + offset;
			*len = n - offset;
			return 0;
		}
	}
}

static int lua_close(void *p)
{
	struct lua_rstream *restrict z = p;
	const int rderr = z->rderr;
	const int err = io_stream_close(z->inner);
	free(z);
	return rderr != 0 ? rderr : err;
}

static struct io_stream *lua_reader_new(struct io_stream *base)
{
	if (base == NULL) {
		return NULL;
	}

	/* Wrap with bufreader so we can peek for gzip magic. io_bufpeek() below
	 * requires specifically an io_bufreader (it asserts the vftable and
	 * reinterprets the object), so wrap unconditionally: a base that already
	 * has direct_read but is not an io_bufreader would otherwise skip the
	 * wrap and fail that assert (or type-confuse under NDEBUG). */
	base = io_bufreader(base, IO_BUFSIZE);
	if (base == NULL) {
		return NULL;
	}

	struct io_stream *inner;
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
		io_stream_close(inner);
		return NULL;
	}

	static const struct io_stream_vftable vftable = {
		.direct_read = lua_direct_read,
		.close = lua_close,
	};
	z->s = (struct io_stream){
		.vftable = &vftable,
		.data = NULL,
	};
	z->inner = inner;
	z->state = LUA_SKIP_BOM;
	z->shebang_confirmed = false;
	z->rderr = 0;
	z->peeklen = 0;
	z->peekpos = 0;
	return (struct io_stream *)z;
}

#if WITH_LUA
const char *codec_lua_stream_read(
	struct lua_State *restrict L, void *ud, size_t *restrict sz)
{
	(void)L;
	struct codec_lua_stream *restrict rs = ud;
	const void *buf;
	/* Lua allows an arbitrary chunk length. */
	*sz = SIZE_MAX;
	const int err = io_stream_direct_read(rs->stream, &buf, sz);
	if (err != 0) {
		LOGE_F("%s %d", rs->errlabel, err);
		/* lua_Reader has no error channel; record it and stop so the
		 * caller can turn it into a load failure instead of letting
		 * lua_load() treat the truncated input as a clean EOF. */
		rs->err = err;
		return NULL;
	}
	if (*sz == 0) {
		return NULL;
	}
	return buf;
}
#endif /* WITH_LUA */

struct io_stream *codec_lua_reader(const char *path)
{
	FILE *f;
	if (strcmp(path, "-") == 0) {
		f = stdin;
	} else {
		f = fopen(path, "rb");
		if (f == NULL) {
			const int err = errno;
			LOGE_F("codec_lua_reader: fopen(\"%s\"): (%d) %s", path,
			       err, strerror(err));
			return NULL;
		}
	}
	struct io_stream *s = io_filereader(f);
	if (s == NULL) {
		/* io_filereader takes ownership of f; given f != NULL here, its
		 * only NULL return is the internal malloc failure, which already
		 * fclose()s f. Closing it again here would be a double-close. */
		LOGOOM();
		return NULL;
	}
	s = lua_reader_new(s);
	if (s == NULL) {
		return NULL;
	}
	return s;
}
