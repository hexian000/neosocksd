/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file codec.c
 * @brief Implementation of compression and decompression codecs
 *
 * This file implements stream-based compression and decompression using the
 * miniz library. It provides DEFLATE/zlib compression writers and inflation
 * readers, as well as gzip header parsing functionality.
 *
 * The implementation uses a streaming approach where:
 * - Writers accept uncompressed data and output compressed data
 * - Readers accept compressed data and output uncompressed data
 * - Internal buffers handle partial reads/writes and data flow control
 */

#include "codec.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "miniz.h"
#include "utils/class.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief DEFLATE compression stream implementation
 *
 * This structure wraps a base stream to provide DEFLATE compression.
 * It maintains internal buffers and state for the compression process.
 */
struct deflate_stream {
	struct stream s;
	struct stream *base;
	tdefl_status status;
	tdefl_compressor deflator;
	size_t dstpos, dstlen;
	unsigned char dstbuf[IO_BUFSIZE];
};
ASSERT_SUPER(struct stream, struct deflate_stream, s);

/**
 * @brief Write data to DEFLATE compression stream
 * @param p Pointer to deflate_stream structure
 * @param buf Input data to compress
 * @param len Pointer to input length; updated with bytes consumed on return
 * @return 0 on success, error code on failure
 *
 * This function compresses input data using DEFLATE and writes the compressed
 * output to the base stream. It handles partial writes and internal buffering.
 * The compression is done incrementally - not all input may be consumed in
 * one call if the output buffer becomes full.
 */
static int deflate_write(void *p, const void *buf, size_t *restrict len)
{
	struct deflate_stream *restrict z = p;
	size_t nwritten = 0;
	const unsigned char *src = buf;
	size_t remain = *len;

	while (remain > 0 && z->status == TDEFL_STATUS_OKAY) {
		/* If output buffer has space, compress more data */
		if (z->dstlen < sizeof(z->dstbuf)) {
			size_t srclen = remain;
			unsigned char *dst = z->dstbuf + z->dstlen;
			size_t dstlen = sizeof(z->dstbuf) - z->dstlen;

			/* Compress data into output buffer */
			z->status = tdefl_compress(
				&z->deflator, src, &srclen, dst, &dstlen,
				TDEFL_NO_FLUSH);
			src += srclen, remain -= srclen;
			z->dstlen += dstlen;
			nwritten += srclen;
		}

		/* Write compressed data from buffer to base stream */
		unsigned char *avail = z->dstbuf + z->dstpos;
		size_t n = z->dstlen - z->dstpos;
		const int err = stream_write(z->base, avail, &n);
		z->dstpos += n;
		if (err != 0) {
			return err;
		}
		if (z->dstpos < z->dstlen) {
			/* Short write - base stream is full */
			return -1;
		}
		/* All output written, reset buffer for next iteration */
		z->dstpos = z->dstlen = 0;
	}

	*len = nwritten;
	if (z->status != TDEFL_STATUS_OKAY) {
		return z->status;
	}
	return 0;
}

/**
 * @brief Internal flush function for DEFLATE stream
 * @param z Pointer to deflate_stream structure
 * @param flush Type of flush operation to perform
 * @return 0 on success, error code on failure
 *
 * This function flushes any pending compressed data from the compressor
 * to the base stream. Different flush modes control how the compressor
 * handles remaining data (sync flush vs final finish).
 */
static int
deflate_flush_(struct deflate_stream *restrict z, const tdefl_flush flush)
{
	do {
		/* Flush any remaining compressed data from compressor */
		unsigned char *buf = z->dstbuf + z->dstlen;
		size_t n = sizeof(z->dstbuf) - z->dstlen;
		z->status = tdefl_compress(
			&z->deflator, NULL, NULL, buf, &n, flush);
		z->dstlen += n;

		/* Write flushed data to base stream */
		buf = z->dstbuf + z->dstpos;
		n = z->dstlen - z->dstpos;
		const int err = stream_write(z->base, buf, &n);
		z->dstpos += n;
		if (err != 0) {
			return err;
		}
		if (z->dstpos < z->dstlen) {
			/* Short write - base stream is full */
			return -1;
		}
		z->dstpos = z->dstlen = 0;

		if (z->status < TDEFL_STATUS_OKAY) {
			return z->status;
		}
	} while (z->status != TDEFL_STATUS_DONE);
	return 0;
}

/**
 * @brief Flush DEFLATE stream (full flush)
 * @param p Pointer to deflate_stream structure
 * @return 0 on success, error code on failure
 *
 * Performs a full flush, emitting a sync point so that the decompressor
 * can restart from this point.  The base stream is also flushed.
 */
static int deflate_flush(void *p)
{
	struct deflate_stream *restrict z = p;
	int ret = deflate_flush_(z, TDEFL_FULL_FLUSH);
	if (ret == 0) {
		ret = stream_flush(z->base);
	}
	return ret;
}

/**
 * @brief Close DEFLATE stream and clean up resources
 * @param p Pointer to deflate_stream structure
 * @return 0 on success, error code on failure
 *
 * Finishes the compression process, flushes all remaining data,
 * closes the base stream, and frees allocated memory.
 */
static int deflate_close(void *p)
{
	struct deflate_stream *restrict z = p;
	const int flusherr = deflate_flush_(z, TDEFL_FINISH);
	const int err = stream_close(z->base);
	free(z);
	return flusherr != 0 ? flusherr : err;
}

/**
 * @brief Create a DEFLATE compression writer (internal function)
 * @param base Base stream to write compressed data to
 * @param zlib Whether to use zlib format (true) or raw DEFLATE (false)
 * @return New compression stream, or NULL on error
 *
 * This internal function creates either a zlib or raw DEFLATE compression
 * stream. The zlib format includes headers and checksums, while raw DEFLATE
 * contains only the compressed data blocks.
 */
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

	/* Set up virtual function table for stream interface */
	static const struct stream_vftable vftable = {
		.write = deflate_write,
		.flush = deflate_flush,
		.close = deflate_close,
	};
	z->s = (struct stream){ &vftable, NULL };
	z->base = base;
	z->status = TDEFL_STATUS_OKAY;

	/* Configure compression flags - zlib header if requested */
	const int flags =
		(zlib ? TDEFL_WRITE_ZLIB_HEADER : 0) | TDEFL_DEFAULT_MAX_PROBES;
	const tdefl_status status = tdefl_init(&z->deflator, NULL, NULL, flags);
	if (status != TDEFL_STATUS_OKAY) {
		stream_close(base);
		free(z);
		return NULL;
	}

	/* Initialize output buffer state */
	z->dstpos = z->dstlen = 0;
	return (struct stream *)z;
}

/* Public API wrapper functions */

struct stream *codec_zlib_writer(struct stream *base)
{
	return deflate_writer(base, true);
}

struct stream *codec_deflate_writer(struct stream *base)
{
	return deflate_writer(base, false);
}

/**
 * @brief DEFLATE decompression stream implementation
 *
 * This structure wraps a base stream to provide DEFLATE decompression.
 * It maintains internal buffers for both input and output data, managing
 * the decompression process incrementally.
 */
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

/**
 * @brief Direct read from DEFLATE decompression stream
 * @param p Pointer to inflate_stream structure
 * @param buf Pointer to buffer pointer; set to point to available data
 * @param len Pointer to length; updated with available data length
 * @return 0 on success, error code on failure
 *
 * This function provides direct access to decompressed data without copying.
 * It manages the decompression pipeline: reading compressed data, decompressing
 * it, and providing pointers to the decompressed output buffer.
 */
static int inflate_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct inflate_stream *restrict z = p;
	do {
		/* If source buffer is empty and not at EOF, read more input */
		if (z->srclen == 0 && !z->srceof) {
			const void *srcbuf;
			size_t n = IO_BUFSIZE;
			z->srcerr = stream_direct_read(z->base, &srcbuf, &n);
			if (n < sizeof(z->srcbuf) || z->srcerr != 0) {
				z->srceof = true;
			}
			z->srclen = n;
			z->srcbuf = srcbuf;
		}

		/* If output buffer is full, wrap around (sliding window) */
		if (z->dstpos == z->dstlen && z->dstlen == sizeof(z->dstbuf)) {
			z->dstpos = z->dstlen = 0;
		}

		/* If we have input data and output space, decompress */
		if (z->srclen > 0 && z->dstlen < sizeof(z->dstbuf) &&
		    z->status > TINFL_STATUS_DONE) {
			const unsigned char *src = z->srcbuf;
			size_t srclen = z->srclen;
			unsigned char *dst = z->dstbuf + z->dstlen;
			size_t dstlen = sizeof(z->dstbuf) - z->dstlen;
			int flags = z->flags;

			/* Tell decompressor if more input is available */
			if (!z->srceof) {
				flags |= TINFL_FLAG_HAS_MORE_INPUT;
			}

			/* Decompress data */
			z->status = tinfl_decompress(
				&z->inflator, src, &srclen, z->dstbuf, dst,
				&dstlen, flags);
			z->srcbuf += srclen;
			z->srclen -= srclen;
			z->dstlen += dstlen;
		}

		/* If we have output data available, return it */
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

	/* No more data available */
	*len = 0;
	if (z->status != TINFL_STATUS_DONE) {
		return z->status;
	}
	return 0;
}

/**
 * @brief Close inflate stream and clean up resources
 * @param p Pointer to inflate_stream structure
 * @return 0 on success, error code on failure
 *
 * Closes the base stream and frees allocated memory.
 */
static int inflate_close(void *p)
{
	struct inflate_stream *restrict z = p;
	const int err = stream_close(z->base);
	free(z);
	return err;
}

/**
 * @brief Create a DEFLATE decompression reader (internal function)
 * @param base Base stream to read compressed data from
 * @param zlib Whether to expect zlib format (true) or raw DEFLATE (false)
 * @return New decompression stream, or NULL on error
 *
 * This internal function creates either a zlib or raw DEFLATE decompression
 * stream. The zlib format includes headers and checksums, while raw DEFLATE
 * contains only the compressed data blocks.
 */
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

	/* Set up virtual function table for stream interface */
	static const struct stream_vftable vftable = {
		.direct_read = inflate_direct_read,
		.close = inflate_close,
	};
	z->s = (struct stream){ &vftable, NULL };
	z->base = base;
	z->srceof = false;
	z->srcerr = 0;
	z->srclen = 0;

	/* Configure decompression flags - zlib header parsing if requested */
	z->flags = zlib ? TINFL_FLAG_PARSE_ZLIB_HEADER : 0;
	z->status = TINFL_STATUS_NEEDS_MORE_INPUT;
	tinfl_init(&z->inflator);

	/* Initialize output buffer state */
	z->dstpos = z->dstlen = 0;
	return (struct stream *)z;
}

/* Public API wrapper functions */

struct stream *codec_zlib_reader(struct stream *base)
{
	return inflate_reader(base, true);
}

struct stream *codec_inflate_reader(struct stream *base)
{
	return inflate_reader(base, false);
}

/* RFC 1952 - gzip format implementation */

/**
 * @brief gzip compression stream implementation
 *
 * Identical layout to deflate_stream, extended with running CRC-32 and
 * uncompressed byte count for the gzip trailer.
 */
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
			/* Update CRC-32 and size over the consumed input */
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

/*
 * Write the 8-byte gzip trailer (CRC-32 then ISIZE) to the base stream.
 * Returns 0 on success, error code on failure.
 */
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

/*
 * Finish the current gzip member: flush the DEFLATE stream, write the
 * trailer, and mark the stream as finished.  The next write will start
 * a new gzip member.  The base stream is also flushed.
 */
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
	z->s = (struct stream){ &vftable, NULL };
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

/**
 * @brief gzip header flag bits (RFC 1952)
 *
 * These flags indicate which optional fields are present in the gzip header.
 */
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

/**
 * @brief gzip decompression stream states
 */
enum gzip_rstate {
	/* Parsing gzip member header */
	GZIP_R_HEADER,
	/* Decompressing DEFLATE body */
	GZIP_R_BODY,
	/* Consuming and validating 8-byte trailer */
	GZIP_R_TRAILER,
};

/**
 * @brief gzip header parser sub-phases
 *
 * These phases track parsing of optional fields within the gzip header.
 */
enum gzip_hphase {
	/* Accumulating fixed 10-byte header */
	GZIP_HPASE_HEADER,
	/* FEXTRA: reading 2-byte xlen (low) */
	GZIP_HPASE_FEXTRA_1,
	/* FEXTRA: skipping xlen bytes */
	GZIP_HPASE_FEXTRA_2,
	/* FNAME: skipping until NUL */
	GZIP_HPASE_FNAME,
	/* FCOMMENT: skipping until NUL */
	GZIP_HPASE_FCOMMENT,
	/* FHCRC: reading low byte */
	GZIP_HPASE_FHCRC_1,
	/* FHCRC: reading high byte and validating */
	GZIP_HPASE_FHCRC_2,
	/* Header parsing complete */
	GZIP_HPASE_DONE,
	/* Special: waiting for second xlen byte */
	GZIP_HPASE_XLEN_2 = 100,
};

/**
 * @brief gzip decompression stream implementation
 *
 * Wraps inflate_stream fields with a state machine that handles the gzip
 * header, body, and trailer for each member, supporting multiframe streams.
 */
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

/*
 * Consume bytes from z->srcbuf to parse the gzip member header.
 * Returns 1 when header is fully parsed, 0 if more input is needed,
 * -1 on format error.
 */
static int gzip_rstream_parse_hdr(struct gzip_rstream *restrict z)
{
	while (z->srclen > 0) {
		unsigned char b = *z->srcbuf;

		switch (z->hphase) {
		case GZIP_HPASE_HEADER:
			z->hdrbuf[z->hdrpos] = b;
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			z->hdrpos++;
			if (z->hdrpos < 10) {
				break;
			}
			/* Validate magic and compression method */
			if (z->hdrbuf[0] != 0x1f || z->hdrbuf[1] != 0x8b ||
			    z->hdrbuf[2] != 0x08) {
				LOGD("gzip: invalid magic");
				return -1;
			}
			z->hdrflg = z->hdrbuf[3];
			/* Advance to first applicable optional-field phase */
			z->hphase = GZIP_HPASE_FEXTRA_1;
			/* fall through */
		case GZIP_HPASE_FEXTRA_1:
			if (!(z->hdrflg & GZIP_FEXTRA)) {
				z->hphase = GZIP_HPASE_FNAME;
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
				z->hphase = GZIP_HPASE_XLEN_2;
				return 0;
			}
			z->xlen_remain = read_uint16_le(z->srcbuf);
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 2);
			z->srcbuf += 2, z->srclen -= 2;
			z->hphase = GZIP_HPASE_FEXTRA_2;
			/* fall through */
		case GZIP_HPASE_FEXTRA_2:
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
			z->hphase = GZIP_HPASE_FNAME;
			/* fall through */
		case GZIP_HPASE_FNAME:
			if (!(z->hdrflg & GZIP_FNAME)) {
				z->hphase = GZIP_HPASE_FCOMMENT;
				break;
			}
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			if (b != 0x00) {
				/* still inside filename */
				return 0;
			}
			z->hphase = GZIP_HPASE_FCOMMENT;
			break;
		case GZIP_HPASE_FCOMMENT:
			if (!(z->hdrflg & GZIP_FCOMMENT)) {
				z->hphase = GZIP_HPASE_FHCRC_1;
				break;
			}
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			if (b != 0x00) {
				return 0;
			}
			z->hphase = GZIP_HPASE_FHCRC_1;
			break;
		case GZIP_HPASE_FHCRC_1:
			if (!(z->hdrflg & GZIP_FHCRC)) {
				z->hphase = GZIP_HPASE_DONE;
				return 1;
			}
			z->hdrbuf[0] = b;
			z->srcbuf++, z->srclen--;
			z->hphase = GZIP_HPASE_FHCRC_2;
			return 0;
		case GZIP_HPASE_FHCRC_2: {
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
			z->hphase = GZIP_HPASE_DONE;
			return 1;
		case GZIP_HPASE_DONE:
			return 1;
		case GZIP_HPASE_XLEN_2:
			z->xlen_remain = (uint_fast16_t)z->hdrbuf[0] |
					 ((uint_fast16_t)b << 8);
			z->hdrcrc = (uint_least32_t)mz_crc32(
				z->hdrcrc, z->srcbuf, 1);
			z->srcbuf++, z->srclen--;
			z->hphase = GZIP_HPASE_FEXTRA_2;
			break;
		default:
			return -1;
		}
	}

	if (z->hphase == GZIP_HPASE_DONE) {
		return 1;
	}
	/* Handle phases that don't consume bytes but need to advance */
	if (z->hphase == GZIP_HPASE_FNAME && !(z->hdrflg & GZIP_FNAME)) {
		z->hphase = GZIP_HPASE_FCOMMENT;
	}
	if (z->hphase == GZIP_HPASE_FCOMMENT && !(z->hdrflg & GZIP_FCOMMENT)) {
		z->hphase = GZIP_HPASE_FHCRC_1;
	}
	if (z->hphase == GZIP_HPASE_FHCRC_1 && !(z->hdrflg & GZIP_FHCRC)) {
		return 1;
	}
	return 0;
}

static int gzip_direct_read(void *p, const void **buf, size_t *restrict len)
{
	struct gzip_rstream *restrict z = p;
	for (;;) {
		/* Refill source buffer when empty */
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

		switch (z->rstate) {
		case GZIP_R_HEADER: {
			if (z->srclen == 0 && z->srceof) {
				/* Clean EOF between members */
				*len = 0;
				return z->srcerr;
			}
			const int hr = gzip_rstream_parse_hdr(z);
			if (hr < 0) {
				*len = 0;
				z->rderr = hr;
				return hr;
			}
			if (hr == 0) {
				if (z->srceof) {
					/* Truncated header */
					*len = 0;
					z->rderr = -1;
					return -1;
				}
				continue;
			}
			/* Header complete - initialise DEFLATE decompressor */
			tinfl_init(&z->inflator);
			z->status = TINFL_STATUS_NEEDS_MORE_INPUT;
			z->crc = (uint_least32_t)MZ_CRC32_INIT;
			z->isize = 0;
			z->dstpos = z->dstlen = 0;
			z->rstate = GZIP_R_BODY;
			continue;
		}
		case GZIP_R_BODY: {
			/* Wrap around sliding window when fully consumed */
			if (z->dstpos == z->dstlen &&
			    z->dstlen == sizeof(z->dstbuf)) {
				z->dstpos = z->dstlen = 0;
			}

			/* Decompress if input and output space are available */
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
					&z->inflator, src, &srclen, z->dstbuf,
					dst, &dstlen, flags);
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
				/* Update CRC-32 and size before returning */
				z->crc = (uint_least32_t)mz_crc32(
					z->crc, z->dstbuf + z->dstpos, n);
				z->isize += (uint_least32_t)n;
				*buf = z->dstbuf + z->dstpos;
				*len = n;
				z->dstpos += n;
				if (z->dstpos == z->dstlen &&
				    z->status == TINFL_STATUS_DONE) {
					z->rstate = GZIP_R_TRAILER;
					z->trailpos = 0;
				}
				return 0;
			}

			if (z->status == TINFL_STATUS_DONE) {
				z->rstate = GZIP_R_TRAILER;
				z->trailpos = 0;
				continue;
			}

			if (z->status < TINFL_STATUS_DONE) {
				*len = 0;
				z->rderr = z->status;
				return z->status;
			}

			if (z->srceof) {
				/* Unexpected EOF inside DEFLATE stream */
				*len = 0;
				z->rderr = -1;
				return -1;
			}
			continue;
		}
		case GZIP_R_TRAILER: {
			/* Consume 8 trailer bytes */
			while (z->trailpos < 8 && z->srclen > 0) {
				z->trail[z->trailpos++] = *z->srcbuf;
				z->srcbuf++, z->srclen--;
			}
			if (z->trailpos < 8) {
				if (z->srceof) {
					LOGD("gzip: short trailer");
					*len = 0;
					z->rderr = -1;
					return -1;
				}
				continue;
			}
			/* Validate CRC-32 */
			const uint_least32_t stored_crc =
				(uint_least32_t)read_uint32_le(z->trail);
			if (stored_crc != z->crc) {
				LOGD("gzip: CRC mismatch");
				*len = 0;
				z->rderr = -1;
				return -1;
			}
			/* Validate ISIZE */
			const uint_least32_t stored_isize =
				(uint_least32_t)read_uint32_le(z->trail + 4);
			if (stored_isize != z->isize) {
				LOGD("gzip: ISIZE mismatch");
				*len = 0;
				z->rderr = -1;
				return -1;
			}
			/* Check for more members */
			if (z->srclen == 0 && z->srceof) {
				*len = 0;
				return z->srcerr;
			}
			/* Reset header parser for next member */
			z->hdrpos = 0;
			z->hphase = GZIP_HPASE_HEADER;
			z->hdrcrc = (uint_least32_t)MZ_CRC32_INIT;
			z->rstate = GZIP_R_HEADER;
			continue;
		}
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
	z->s = (struct stream){ &vftable, NULL };
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
	z->hphase = GZIP_HPASE_HEADER;
	z->hdrcrc = (uint_least32_t)MZ_CRC32_INIT;
	z->dstpos = z->dstlen = 0;
	return (struct stream *)z;
}
