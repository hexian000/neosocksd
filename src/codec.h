/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CODEC_H
#define CODEC_H

#include <stddef.h>

struct stream;

/* RFC 1950 */
struct stream *codec_zlib_writer(struct stream *base);
struct stream *codec_zlib_reader(struct stream *base);

/* RFC 1951 */
struct stream *codec_deflate_writer(struct stream *base);
struct stream *codec_inflate_reader(struct stream *base);

/* RFC 1952 */
const void *gzip_unbox(const void *p, size_t *len);

#endif /* CODEC_H */
