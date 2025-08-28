/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CODEC_H
#define CODEC_H

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
 * @brief Extract DEFLATE data from gzip format
 * @param p Pointer to gzip data
 * @param len Pointer to data length; updated with DEFLATE data length on success
 * @return Pointer to DEFLATE data within the gzip stream, or NULL on error
 * 
 * Parses a gzip header to extract the raw DEFLATE data portion. This function
 * validates the gzip magic numbers, compression method, and optional fields
 * like filename and comments. The returned pointer points into the original
 * data buffer at the start of the DEFLATE stream.
 * 
 * Note: This only extracts the DEFLATE portion - use codec_inflate_reader()
 * to actually decompress the data.
 */
const void *gzip_unbox(const void *p, size_t *len);

#endif /* CODEC_H */
