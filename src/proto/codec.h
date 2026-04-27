/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef PROTO_CODEC_H
#define PROTO_CODEC_H

#include <stddef.h>

/**
 * @file codec.h
 * @brief Compression and decompression codec implementations
 *
 * This module provides stream-based compression and decompression codecs
 * for DEFLATE, zlib, and gzip formats. The codecs wrap base streams to
 * provide transparent compression/decompression functionality.
 */

struct stream;

/* RFC 1950 - zlib format (DEFLATE with adler32 checksum) */

/**
 * @brief Create a zlib compression writer stream
 * @param base The base stream to write compressed data to
 * @return A new stream that compresses data using zlib format, or NULL on error
 *
 * Creates a compression stream that accepts uncompressed data and writes
 * zlib-formatted compressed data to the base stream. The zlib format includes
 * a header and adler32 checksum for data integrity.
 *
 * Flushing performs a full DEFLATE flush (emitting a sync point) and
 * propagates the flush to the base stream.
 */
struct stream *codec_zlib_writer(struct stream *base);

/**
 * @brief Create a zlib decompression reader stream
 * @param base The base stream to read compressed data from
 * @return A new stream that decompresses zlib data, or NULL on error
 *
 * Creates a decompression stream that reads zlib-formatted compressed data
 * from the base stream and provides uncompressed data through the read interface.
 * Validates the zlib header and adler32 checksum.
 */
struct stream *codec_zlib_reader(struct stream *base);

/* RFC 1951 - raw DEFLATE format */

/**
 * @brief Create a raw DEFLATE compression writer stream
 * @param base The base stream to write compressed data to
 * @return A new stream that compresses data using raw DEFLATE, or NULL on error
 *
 * Creates a compression stream that accepts uncompressed data and writes
 * raw DEFLATE compressed data to the base stream. This format has no header
 * or checksum - just the compressed data blocks.
 *
 * Flushing performs a full DEFLATE flush (emitting a sync point) and
 * propagates the flush to the base stream.
 */
struct stream *codec_deflate_writer(struct stream *base);

/**
 * @brief Create a raw DEFLATE decompression reader stream
 * @param base The base stream to read compressed data from
 * @return A new stream that decompresses raw DEFLATE data, or NULL on error
 *
 * Creates a decompression stream that reads raw DEFLATE compressed data
 * from the base stream and provides uncompressed data. Expects no header
 * or checksum validation.
 */
struct stream *codec_inflate_reader(struct stream *base);

/* RFC 1952 - gzip format */

/**
 * @brief Create a gzip compression writer stream
 * @param base The base stream to write compressed data to
 * @return A new stream that compresses data using gzip format, or NULL on error
 *
 * Creates a compression stream that writes gzip members with a static 10-byte
 * header (MTIME=0, OS=0xff), raw DEFLATE compressed data, and an 8-byte
 * trailer containing CRC-32 and ISIZE of the uncompressed input.
 *
 * Flushing finishes the current gzip member (DEFLATE finish + trailer) and
 * starts a new one on the next write, producing a multi-member gzip stream.
 * The base stream is also flushed.
 */
struct stream *codec_gzip_writer(struct stream *base);

/**
 * @brief Create a gzip decompression reader stream
 * @param base The base stream to read compressed data from
 * @return A new stream that decompresses gzip data, or NULL on error
 *
 * Creates a decompression stream that reads one or more concatenated gzip
 * members, verifying each member's CRC-32 and ISIZE trailer fields.
 * Supports all standard gzip header optional fields (FEXTRA, FNAME, FCOMMENT,
 * FHCRC). Returns an error if any checksum does not match.
 */
struct stream *codec_gzip_reader(struct stream *base);

#endif /* PROTO_CODEC_H */
