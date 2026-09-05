/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CODEC_BASE64_H
#define CODEC_BASE64_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup base64
 * @brief RFC 4648: The Base16, Base32, and Base64 Data Encodings
 * @{
 */

/**
 * @brief Encode data with Base64.
 * @param[out] dst Output buffer, or NULL to query required size.
 * @param[inout] dstlen On input: output buffer size; not read when dst is
 *                       NULL. On output (always set): the encoded data
 *                       length, which is also the size a too-small buffer
 *                       must grow to, or 0 if the length computation
 *                       overflowed.
 * @param[in] src Raw data buffer.
 * @param srclen Raw data length in bytes.
 * @return true if the data was encoded, or if a size query (dst == NULL)
 *         computed the required length.
 *         false if the encoded length overflows size_t, or dst is not NULL
 *         and the buffer is too small.
 * @note A size query never fails for lack of buffer space, but it runs the
 *       same length computation as a real call, so it still returns false on
 *       overflow.
 * @note Null terminator is not added to output.
 * @note No memory allocations are performed.
 * @warning The buffers must not overlap (in-place encoding is not supported).
 * @par Example
 * @code
 * // Calculate required buffer size
 * size_t len = 0;
 * base64_encode(NULL, &len, data, datalen);
 * // Allocate and encode
 * unsigned char *buf = malloc(len);
 * base64_encode(buf, &len, data, datalen);
 * @endcode
 */
bool base64_encode(
	unsigned char *restrict dst, size_t *restrict dstlen,
	const unsigned char *restrict src, size_t srclen);

/**
 * @brief Decode data with Base64.
 * @param[out] dst Output buffer, or NULL to query required size.
 * @param[inout] dstlen On input: output buffer size; not read when dst is
 *                       NULL. On output (always set): the decoded data
 *                       length, which is also the size a too-small buffer
 *                       must grow to, or 0 if srclen or the encoded data is
 *                       invalid.
 * @param[in] src Base64 encoded data buffer.
 * @param srclen Encoded data length (must be a multiple of 4).
 * @return true if the data was decoded, or if a size query (dst == NULL)
 *         computed the required length.
 *         false if srclen is not a multiple of 4, or dst is not NULL and
 *         either the buffer is too small or the encoded data is invalid.
 * @note A size query checks srclen but not the encoded data: it returns false
 *       when srclen is not a multiple of 4, and otherwise returns true with
 *       the length the input would decode to, including for data that a real
 *       decode rejects. It reads the trailing padding of src, so its answer
 *       depends on the input rather than on srclen alone.
 * @note No memory allocations are performed.
 * @note In-place decoding is supported (dst == src), since decoded data
 *       is always smaller than or equal to encoded data.
 * @note On failure the output buffer holds an unspecified number of decoded
 *       bytes: every group is written as it is decoded and only the group
 *       carrying the invalid byte is rejected, so decoding in place destroys
 *       the leading bytes of the input. A caller that still needs the
 *       encoded text after a rejection must decode elsewhere or keep a copy.
 *       Only the checks made before any write — srclen not a multiple of 4,
 *       and a too-small dst — leave the buffer byte-for-byte intact.
 * @note Decoding is lenient about padding: the bits of a padded group that
 *       belong to the dropped byte(s) are discarded without checking they are
 *       zero, so a non-canonical encoding (e.g. "QR==" as well as "QQ==")
 *       decodes to the same output rather than being rejected. RFC 4648 §3.5
 *       only recommends rejecting such input.
 * @warning If dst != src, the buffers must not overlap.
 * @par Example
 * @code
 * // Calculate required buffer size
 * size_t len = 0;
 * base64_decode(NULL, &len, encoded, encodedlen);
 * // Allocate and decode
 * unsigned char *buf = malloc(len);
 * base64_decode(buf, &len, encoded, encodedlen);
 * @endcode
 */
bool base64_decode(
	unsigned char *dst, size_t *restrict dstlen, const unsigned char *src,
	size_t srclen);

/** @} */

#endif /* CODEC_BASE64_H */
