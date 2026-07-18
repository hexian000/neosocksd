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
 * @param[inout] dstlen On input: output buffer size.
 *                       On output: encoded data length (always set).
 * @param[in] src Raw data buffer.
 * @param srclen Raw data length in bytes.
 * @return true if successfully completed or dst is NULL.
 *         false if buffer too small or integer overflow.
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
 * @param[inout] dstlen On input: output buffer size.
 *                       On output: decoded data length (0 on format error).
 * @param[in] src Base64 encoded data buffer.
 * @param srclen Encoded data length (must be a multiple of 4).
 * @return true if successfully completed or dst is NULL.
 *         false if invalid input, buffer too small, or srclen not multiple of 4.
 * @note No memory allocations are performed.
 * @note In-place decoding is supported (dst == src), since decoded data
 *       is always smaller than or equal to encoded data.
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
