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
#include "utils/class.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include "miniz.h"

#include <inttypes.h>
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
 * @brief Flush DEFLATE stream (sync flush)
 * @param p Pointer to deflate_stream structure
 * @return 0 on success, error code on failure
 *
 * Performs a synchronization flush, ensuring all pending input is
 * compressed and written while maintaining the ability to continue
 * compression.
 */
static int deflate_flush(void *p)
{
	struct deflate_stream *restrict z = p;
	return deflate_flush_(z, TDEFL_SYNC_FLUSH);
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
ASSERT_SUPER(struct stream, struct deflate_stream, s);

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
 * @brief gzip header flag bits (RFC 1952)
 *
 * These flags indicate which optional fields are present in the gzip header.
 */
enum gzip_flags {
	GZIP_FTEXT = 1 << 0, /**< File is probably ASCII text */
	GZIP_FHCRC = 1 << 1, /**< Header CRC16 is present */
	GZIP_FEXTRA = 1 << 2, /**< Extra field is present */
	GZIP_FNAME = 1 << 3, /**< Original filename is present */
	GZIP_FCOMMENT = 1 << 4, /**< File comment is present */
};

const void *gzip_unbox(const void *p, size_t *restrict len)
{
	const unsigned char *restrict b = p;
	size_t n = *len;

	/* Check minimum header size (10 bytes) */
	if (n < 10) {
		return NULL;
	}

	/* Parse fixed gzip header fields */
	const struct {
		uint8_t id1, id2; /**< Magic numbers (0x1f, 0x8b) */
		uint8_t cm, flg; /**< Compression method and flags */
		uint32_t mtime; /**< Modification time */
		uint8_t xfl, os; /**< Extra flags and OS identifier */
	} header = {
		.id1 = read_uint8(b + 0),
		.id2 = read_uint8(b + 1),
		.cm = read_uint8(b + 2),
		.flg = read_uint8(b + 3),
		.mtime = read_uint32_le(b + 4),
		.xfl = read_uint8(b + 8),
		.os = read_uint8(b + 9),
	};

	/* Validate gzip magic numbers and compression method */
	if (header.id1 != 0x1f || header.id2 != 0x8b || header.cm != 0x08) {
		LOGD("gzip: unsupported header");
		return NULL;
	}
	b += 10, n -= 10;
	/* Parse optional extra field */
	if (header.flg & GZIP_FEXTRA) {
		if (n < 2) {
			return NULL;
		}
		const uint16_t xlen = read_uint16_le(b);
		b += 2, n -= 2;
		if (n < xlen) {
			return NULL;
		}
		b += xlen, n -= xlen;
	}

	/* Parse optional filename field */
	if (header.flg & GZIP_FNAME) {
		const char *name = (char *)b;
		const size_t slen = strnlen(name, n) + 1;
		if (slen >= n) {
			return NULL;
		}
		b += slen, n -= slen;
		LOGD_F("gzip: NAME `%s'", name);
	}

	/* Parse optional comment field */
	if (header.flg & GZIP_FCOMMENT) {
		const char *comment = (char *)b;
		const size_t slen = strnlen(comment, n) + 1;
		if (slen >= n) {
			return NULL;
		}
		b += slen, n -= slen;
		LOGD_F("gzip: COMMENT `%s'", comment);
	}

	/* Validate optional header CRC */
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

	/* Check for trailing CRC32 and ISIZE fields (8 bytes) */
	if (n < 8) {
		LOGD("gzip: short tailer");
		return NULL;
	}

	/* Parse trailer fields (not validated) */
	const struct {
		uint32_t crc; /**< CRC32 of uncompressed data */
		uint32_t isize; /**< Size of uncompressed data modulo 2^32 */
	} tailer = {
		.crc = read_uint32_le(b + n - 8),
		.isize = read_uint32_le(b + n - 4),
	};
	LOGD_F("gzip: original size %" PRIu32 " bytes", tailer.isize);

	/* Return pointer to DEFLATE data and update length */
	*len = n - 8;
	return b;
}
