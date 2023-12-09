/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
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
 * @brief Buffered stream reader.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] bufsize Size of buffer in bytes, 0 for default.
 * @return If malloc failed or f == NULL, returns NULL.
 */
struct stream *io_bufreader(struct stream *base, size_t bufsize);

/**
 * @brief Buffered stream writer.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] bufsize Size of buffer in bytes, 0 for default.
 * @return If malloc failed or f == NULL, returns NULL.
 */
struct stream *io_bufwriter(struct stream *base, size_t bufsize);

/** @} */

#endif /* IO_MEMORY_H */
