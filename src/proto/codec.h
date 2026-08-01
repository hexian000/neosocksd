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

struct io_stream;

/* RFC 1950 - zlib format (DEFLATE with adler32 checksum) */

/**
 * @brief Create a zlib compression writer stream
 * @param base The base stream to write compressed data to
 * @return New stream, or NULL on error
 *
 * Flushing performs a full DEFLATE flush (emitting a sync point) and
 * propagates the flush to the base stream.
 */
struct io_stream *codec_zlib_writer(struct io_stream *base);

/**
 * @brief Create a zlib decompression reader stream
 * @param base The base stream to read compressed data from
 * @return New stream, or NULL on error; validates zlib header and adler32 checksum
 */
struct io_stream *codec_zlib_reader(struct io_stream *base);

/* RFC 1951 - raw DEFLATE format */

/**
 * @brief Create a raw DEFLATE compression writer stream
 * @param base The base stream to write compressed data to
 * @return New stream, or NULL on error
 *
 * No header or checksum — raw compressed data blocks only.
 * Flushing performs a full DEFLATE flush (emitting a sync point) and
 * propagates the flush to the base stream.
 */
struct io_stream *codec_deflate_writer(struct io_stream *base);

/**
 * @brief Create a raw DEFLATE decompression reader stream
 * @param base The base stream to read compressed data from
 * @return New stream, or NULL on error; no header or checksum validation
 */
struct io_stream *codec_inflate_reader(struct io_stream *base);

/* RFC 1952 - gzip format */

/**
 * @brief Create a gzip compression writer stream
 * @param base The base stream to write compressed data to
 * @return New stream, or NULL on error
 *
 * Writes gzip members with a static 10-byte header (MTIME=0, OS=0xff) and
 * an 8-byte trailer (CRC-32 + ISIZE). Flushing finishes the current member
 * and starts a new one on the next write (multi-member gzip stream).
 */
struct io_stream *codec_gzip_writer(struct io_stream *base);

/**
 * @brief Create a gzip decompression reader stream
 * @param base The base stream to read compressed data from
 * @return New stream, or NULL on error
 *
 * Reads concatenated gzip members; verifies CRC-32 and ISIZE per member.
 * Supports all standard header optional fields (FEXTRA, FNAME, FCOMMENT, FHCRC).
 */
struct io_stream *codec_gzip_reader(struct io_stream *base);

/**
 * @brief Create a Lua source reader; auto-detects gzip, strips UTF-8 BOM and shebang
 * @param path File path
 * @return Stream (caller owns; close with io_stream_close()), or NULL on error
 */
struct io_stream *codec_lua_reader(const char *path);

#if WITH_LUA
struct lua_State;

/* State for codec_lua_stream_read: the stream to pull from (borrowed, not
 * closed by the reader), the read-error log prefix (logged verbatim before the
 * error code, e.g. "config: read error"), and an out slot for the error code
 * lua_load() cannot otherwise observe. */
struct codec_lua_stream {
	struct io_stream *stream;
	const char *errlabel;
	int err;
};

/**
 * @brief lua_Reader that streams an io_stream into lua_load().
 *
 * Reads the next chunk via io_stream_direct_read(). On a read error it logs
 * "<errlabel> <n>", records the error in the codec_lua_stream (so the caller
 * can turn a truncated read into a load failure rather than a clean EOF), and
 * stops. @p ud must point at a struct codec_lua_stream.
 */
const char *codec_lua_stream_read(
	struct lua_State *restrict L, void *ud, size_t *restrict sz);
#endif /* WITH_LUA */

#endif /* PROTO_CODEC_H */
