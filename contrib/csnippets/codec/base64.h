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
 * @param dst Output buffer.
 * @param[inout] dstlen Output buffer size / encoded data length.
 * @param src Raw data buffer.
 * @param srclen Raw data length.
 * @return true if successfully completed.
 * @details Null terminator is not added to output.
 * No allocations, the buffers should not overlap.
 * Use `(void)base64_encode(NULL, &len, data, datalen);` to calculate encoded length.
 */
bool base64_encode(
	unsigned char *dst, size_t *dstlen, const unsigned char *src,
	size_t srclen);

/**
 * @brief Decode data with Base64.
 * @param dst Output buffer.
 * @param[inout] dstlen Output buffer size / encoded data length.
 * @param src Raw data buffer.
 * @param srclen Raw data length.
 * @return true if successfully completed.
 * @details No allocations, the buffers should be the same or not overlap at all.
 * Use `(void)base64_decode(NULL, &len, data, datalen);` to calculate decoded length.
 */
bool base64_decode(
	unsigned char *dst, size_t *dstlen, const unsigned char *src,
	size_t srclen);

/** @} */

#endif /* CODEC_BASE64_H */
