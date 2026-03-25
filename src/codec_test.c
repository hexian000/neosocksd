/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "codec.h"

#include "io/memory.h"
#include "io/stream.h"
#include "miniz.h"
#include "utils/buffer.h"
#include "utils/testing.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool stream_write_all(
	struct stream *restrict s, const void *restrict data, const size_t len)
{
	size_t total = 0;
	const unsigned char *p = data;

	while (total < len) {
		size_t n = len - total;
		if (stream_write(s, p + total, &n) != 0) {
			return false;
		}
		if (n == 0) {
			return false;
		}
		total += n;
	}
	return true;
}

static bool stream_read_exact(
	struct stream *restrict s, void *restrict out, const size_t len)
{
	size_t total = 0;
	unsigned char *p = out;

	while (total < len) {
		size_t n = len - total;
		if (stream_read(s, p + total, &n) != 0) {
			return false;
		}
		if (n == 0) {
			return false;
		}
		total += n;
	}
	return true;
}

T_DECLARE_CASE(codec_null_base)
{
	T_EXPECT(codec_zlib_writer(NULL) == NULL);
	T_EXPECT(codec_deflate_writer(NULL) == NULL);
	T_EXPECT(codec_zlib_reader(NULL) == NULL);
	T_EXPECT(codec_inflate_reader(NULL) == NULL);
}

T_DECLARE_CASE(codec_zlib_roundtrip)
{
	enum { N = 16384 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	struct vbuffer *compressed = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 37U) & 0xffU);
	}
	compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);

	w = codec_zlib_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N / 3));
	T_EXPECT(stream_write_all(w, src + (N / 3), N - (N / 3)));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	T_CHECK(compressed != NULL);
	T_EXPECT(VBUF_LEN(compressed) > 0);

	r = codec_zlib_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	r = NULL;

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(compressed);
}

T_DECLARE_CASE(codec_deflate_roundtrip)
{
	enum { N = 8192 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	struct vbuffer *compressed = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 13U + 17U) & 0xffU);
	}
	compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);

	w = codec_deflate_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	T_CHECK(compressed != NULL);
	T_EXPECT(VBUF_LEN(compressed) > 0);

	r = codec_inflate_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	r = NULL;

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(compressed);
}

T_DECLARE_CASE(gzip_unbox_valid_minimal)
{
	static const uint_least8_t gzip_data[] = {
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86,
		0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	};
	size_t len = sizeof(gzip_data);
	const void *deflate_data = gzip_unbox(gzip_data, &len);

	T_CHECK(deflate_data != NULL);
	T_EXPECT(deflate_data == gzip_data + 10);
	T_EXPECT_EQ(len, (size_t)7);
	T_EXPECT_MEMEQ(deflate_data, gzip_data + 10, len);
}

T_DECLARE_CASE(gzip_unbox_with_fname_comment)
{
	static const uint_least8_t gzip_data[] = {
		0x1f, 0x8b, 0x08, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'f',  'i',  'l',	'e',  '.',  't',  'x',	't',
		0x00, 'c',  'o',  'm',	'm',  'e',  'n',  't',	0x00,
		0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6,
		0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	};
	size_t len = sizeof(gzip_data);
	const uint_least8_t *deflate_data = gzip_unbox(gzip_data, &len);

	T_CHECK(deflate_data != NULL);
	T_EXPECT_EQ(len, (size_t)7);
	T_EXPECT_MEMEQ(deflate_data, gzip_data + sizeof(gzip_data) - 15, len);
}

T_DECLARE_CASE(gzip_unbox_fhcrc)
{
	uint_least8_t gzip_data[] = {
		0x1f, 0x8b, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
		0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	};
	size_t len = sizeof(gzip_data);
	const uint_least16_t crc16 = (uint_least16_t)mz_crc32(0, gzip_data, 10);
	const void *deflate_data;

	gzip_data[10] = (uint_least8_t)(crc16 & 0xffU);
	gzip_data[11] = (uint_least8_t)((crc16 >> 8) & 0xffU);

	deflate_data = gzip_unbox(gzip_data, &len);
	T_CHECK(deflate_data != NULL);
	T_EXPECT_EQ(len, (size_t)7);

	gzip_data[10] ^= 0x5a;
	len = sizeof(gzip_data);
	T_EXPECT(gzip_unbox(gzip_data, &len) == NULL);
}

T_DECLARE_CASE(gzip_unbox_invalid_inputs)
{
	static const uint_least8_t short_data[] = { 0x1f, 0x8b, 0x08, 0x00 };
	static const uint_least8_t bad_magic[] = {
		0x1f, 0x8a, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	};
	static const uint_least8_t no_trailer[] = {
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0xcb, 0x48,
	};
	size_t len;

	len = sizeof(short_data);
	T_EXPECT(gzip_unbox(short_data, &len) == NULL);

	len = sizeof(bad_magic);
	T_EXPECT(gzip_unbox(bad_magic, &len) == NULL);

	len = sizeof(no_trailer);
	T_EXPECT(gzip_unbox(no_trailer, &len) == NULL);
}

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, codec_null_base);
	T_RUN_CASE(t, codec_zlib_roundtrip);
	T_RUN_CASE(t, codec_deflate_roundtrip);
	T_RUN_CASE(t, gzip_unbox_valid_minimal);
	T_RUN_CASE(t, gzip_unbox_with_fname_comment);
	T_RUN_CASE(t, gzip_unbox_fhcrc);
	T_RUN_CASE(t, gzip_unbox_invalid_inputs);

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
