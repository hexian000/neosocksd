/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_STREAM_H
#define IO_STREAM_H

#include "io.h"

#include <stddef.h>

/**
 * @defgroup stream
 * @brief Generic streaming IO interface for module decoupling.
 * @{
 */

struct stream_vftable {
	io_direct_reader direct_read;
	io_reader read;
	io_writer write;
	io_flusher flush;
	io_closer close;
};

struct stream {
	const struct stream_vftable *restrict vftable;
	void *data;
};

/**
 * @brief Read a stream directly from the internal buffer. (optional support)
 * @param[in] s The stream.
 * @param[out] buf Pointer to the internal buffer.
 * @param[inout] len Max length / returned length.
 * @return Error code, 0 for OK.
 * @details Any output length > 0 should be considered normal.
 */
int stream_direct_read(struct stream *s, const void **buf, size_t *len);

/**
 * @brief Read from a stream.
 * @param[in] s The stream.
 * @param[out] buf The read buffer.
 * @param[inout] len Buffer size / returned length.
 * @return Error code, 0 for OK.
 * @details The buffer should be filled up whenever possible.
 * Caller can assume short read as EOF or error.
 */
int stream_read(struct stream *s, void *buf, size_t *len);

/**
 * @brief Write to a stream.
 * @param[in] s The stream.
 * @param[in] buf Data to write.
 * @param[inout] len Data length / consumed length.
 * @return Error code, 0 for OK.
 * @details All data should be written whenever possible.
 * Caller can assume short write as error.
 */
int stream_write(struct stream *s, const void *buf, size_t *len);

/**
 * @brief Flush a stream.
 * @param[in] s The stream.
 * @return Error code, 0 for OK.
 * @details Base stream is flushed too. If error occurs,
 * stop flushing and return the error.
 */
int stream_flush(struct stream *s);

/**
 * @brief Close a stream.
 * @param[in] s The stream.
 * @return Error code, 0 for OK.
 * @details Base stream is closed too. If error occurs,
 * still close all resources and return the first error.
 */
int stream_close(struct stream *s);

/**
 * @brief Copy all data from one stream to another.
 * @param[in] dst The destination stream.
 * @param[in] src The source stream.
 * @param[in] buf Buffer used for copy.
 * @param[in] bufsize Size of buffer in bytes.
 * @return Error code, 0 for OK.
 */
int stream_copy(
	struct stream *dst, struct stream *src, void *buf, size_t bufsize);

/** @} */

#endif /* IO_STREAM_H */
