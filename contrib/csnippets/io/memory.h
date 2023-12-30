/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_MEMORY_H
#define IO_MEMORY_H

#include "stream.h"

#include <stddef.h>

/**
 * @defgroup memory
 * @brief Streaming wrapper for memory.
 * @{
 */

/**
 * @brief Fixed-size buffer reader.
 * @param[in] buf The buffer.
 * @param[in] bufsize Size of buffer in bytes.
 * @return If malloc failed or buf == NULL, returns NULL.
 */
struct stream *io_memreader(const void *buf, size_t bufsize);

/**
 * @brief Fixed-size buffer writer.
 * @param[in] buf The buffer.
 * @param[in] bufsize Size of buffer in bytes.
 * @param[in] nwritten Counter of bytes written.
 * @return If malloc failed or buf == NULL, returns NULL.
 */
struct stream *io_memwriter(void *buf, size_t bufsize, size_t *nwritten);

struct vbuffer;

/**
 * @brief Heap buffer writer.
 * @param[in] pvbuf Pointer to the heap buffer.
 * @return If malloc failed or pvbuf == NULL, returns NULL.
 */
struct stream *io_heapwriter(struct vbuffer **pvbuf);

/**
 * @brief Print to a heapwriter.
 * @param[in] s If not a valid heapwriter, the behavior is undefined.
 * @param[in] format Same as printf.
 * @return Error code, 0 for OK.
 * @details Stream internal buffer have a limited size.
 */
int io_heapprintf(struct stream *s, const char *format, ...);

/**
 * @brief Buffered stream reader.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] bufsize Size of buffer in bytes, 0 for default.
 * @details Wraps the base stream to support all read methods.
 * @return If malloc failed or base == NULL, returns NULL.
 */
struct stream *io_bufreader(struct stream *base, size_t bufsize);

/**
 * @brief Buffered stream writer.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] bufsize Size of buffer in bytes, 0 for default.
 * @details Wraps the base stream to support all write methods.
 * @return If malloc failed or base == NULL, returns NULL.
 */
struct stream *io_bufwriter(struct stream *base, size_t bufsize);

/**
 * @brief Print to a bufwriter.
 * @param[in] s If not a valid bufwriter, the behavior is undefined.
 * @param[in] format Same as printf.
 * @return Error code, 0 for OK.
 * @details Any invocation writes all buffered data to the base stream.
 * The printed string is truncated to (bufsize - 1) silently.
 */
int io_bufprintf(struct stream *s, const char *format, ...);

/**
 * @brief Metered stream.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] meter Pointer to byte counter.
 * @return If malloc failed or base == NULL, returns NULL.
 */
struct stream *io_metered(struct stream *base, size_t *meter);

/** @} */

#endif /* IO_MEMORY_H */
