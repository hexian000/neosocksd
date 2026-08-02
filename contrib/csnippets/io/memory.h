/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_MEMORY_H
#define IO_MEMORY_H

#include "stream.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup memory
 * @brief Streaming wrapper for memory.
 * @details The writers here differ in how they report running out of room, and
 * a caller that swaps one backing stream for another must account for it:
 * - `io_memwriter` has a fixed buffer, so exhausting it is an expected end
 *   state, not a failure. It returns 0 with a short `*len`, which per
 *   `io_stream_write`'s contract the caller must still treat as an error.
 * - `io_heapwriter` grows until the allocator refuses, so exhaustion *is* a
 *   failure: it returns -1.
 * The sibling writers elsewhere follow the second shape -- `fd_write` returns
 * the errno and `file_write` returns -1 -- so `io_memwriter` is the one whose
 * short write arrives with a success code.
 * @{
 */

/**
 * @brief Fixed-size buffer reader.
 * @param[in] buf The buffer.
 * @param[in] bufsize Size of buffer in bytes.
 * @return If malloc failed or buf == NULL, returns NULL.
 */
struct io_stream *io_memreader(const void *buf, size_t bufsize);

/**
 * @brief Fixed-size buffer writer.
 * @param[in] buf The buffer.
 * @param[in] bufsize Size of buffer in bytes.
 * @param[out] nwritten Running total of bytes written, incremented by each
 * write. May be NULL, in which case nothing is counted.
 * @return If malloc failed or buf == NULL, returns NULL.
 * @details Writing past the end of the buffer is not an error: the write
 * consumes what fits, reports it in `*len` and returns 0. See the group
 * description for how the sibling writers differ.
 */
struct io_stream *io_memwriter(void *buf, size_t bufsize, size_t *nwritten);

struct vbuffer;

/**
 * @brief Heap buffer writer.
 * @param[in] pvbuf Pointer to the heap buffer.
 * @return If malloc failed or pvbuf == NULL, returns NULL.
 * @details `*pvbuf` may be NULL -- the state `VBUF_NEW` returns on allocation
 * failure, and the one `VBUF_HAS_OOM` reports as OOM. Writes to a stream in
 * that state fail with -1 rather than dereferencing it, so a caller may carry
 * a failed `VBUF_NEW` this far and find out at the write.
 */
struct io_stream *io_heapwriter(struct vbuffer **pvbuf);

/**
 * @brief Print to a heapwriter.
 * @param[in] s If not a valid heapwriter, the behavior is undefined.
 * @param[in] format Same as printf.
 * @param[in] ... Same as printf.
 * @return Error code, 0 for OK.
 * @details The heap buffer grows to fit, so unlike `io_bufprintf` the output
 * is never silently truncated: the only failure is the allocator refusing to
 * grow it (or `*pvbuf` already being NULL), which returns an error.
 */
int io_heapprintf(struct io_stream *s, const char *format, ...);

/**
 * @brief Buffered stream reader.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] bufsize Size of buffer in bytes, 0 for default.
 * @details Wraps the base stream to support all read methods.
 * @return If malloc failed or base == NULL, returns NULL.
 */
struct io_stream *io_bufreader(struct io_stream *base, size_t bufsize);

/**
 * @brief Peek at buffered data without consuming it.
 * @param[in] s Must be a stream created by io_bufreader().
 * @param[out] buf Internal buffer pointer (valid until next read/peek/close).
 * @param[inout] len Max requested / actual bytes returned.
 * @return Error code, 0 for OK.
 * @details Returns a zero-copy pointer up to bufsize bytes.
 * Data is not consumed; the next read or peek returns the same bytes.
 * If the buffer is empty, the underlying stream is read to fill it.
 */
int io_bufpeek(struct io_stream *s, const void **buf, size_t *len);

/**
 * @brief Buffered stream writer.
 * @param[in] base Transfer ownership of the base stream.
 * @param[in] bufsize Size of buffer in bytes, 0 for default.
 * @details Wraps the base stream to support all write methods.
 * @return If malloc failed or base == NULL, returns NULL.
 */
struct io_stream *io_bufwriter(struct io_stream *base, size_t bufsize);

/**
 * @brief Print to a bufwriter.
 * @param[in] s If not a valid bufwriter, the behavior is undefined.
 * @param[in] format Same as printf.
 * @param[in] ... Same as printf.
 * @return Error code, 0 for OK.
 * @details Any invocation writes all buffered data to the base stream.
 * The printed string is truncated to (bufsize - 1) silently.
 */
int io_bufprintf(struct io_stream *s, const char *format, ...);

/**
 * @brief Metered stream.
 * @param[in] base Transfer ownership of the base stream.
 * @param[out] meter Running total of bytes transferred, incremented by each
 * read and write. May be NULL, in which case nothing is counted.
 * @return If malloc failed or base == NULL, returns NULL.
 * @details The counter accumulates over the whole lifetime of the stream, with
 * no bound from the base stream's size, so it is at least 64 bits wide
 * regardless of the platform's `size_t` -- a long-lived stream metered in a
 * 32-bit `size_t` would wrap after 4 GiB.
 */
struct io_stream *io_metered(struct io_stream *base, uint_least64_t *meter);

/** @} */

#endif /* IO_MEMORY_H */
