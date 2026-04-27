/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "codec.h"

#include "io/memory.h"
#include "io/stream.h"
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
	T_EXPECT(codec_gzip_writer(NULL) == NULL);
	T_EXPECT(codec_gzip_reader(NULL) == NULL);
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

T_DECLARE_CASE(codec_gzip_roundtrip)
{
	enum { N = 16384 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	struct vbuffer *compressed = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 53U + 7U) & 0xffU);
	}
	compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);

	w = codec_gzip_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N / 2));
	T_EXPECT(stream_write_all(w, src + (N / 2), N - (N / 2)));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	T_CHECK(compressed != NULL);
	T_EXPECT(VBUF_LEN(compressed) > 0);

	r = codec_gzip_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	r = NULL;

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(compressed);
}

T_DECLARE_CASE(codec_gzip_multiframe)
{
	enum { N = 4096 };
	uint_least8_t src1[N], src2[N];
	uint_least8_t out[N * 2];
	struct vbuffer *frame1 = NULL, *frame2 = NULL, *combined = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src1[i] = (uint_least8_t)((i * 11U) & 0xffU);
		src2[i] = (uint_least8_t)((i * 17U + 3U) & 0xffU);
	}
	frame1 = VBUF_NEW(64);
	frame2 = VBUF_NEW(64);
	T_CHECK(frame1 != NULL);
	T_CHECK(frame2 != NULL);

	w = codec_gzip_writer(io_heapwriter(&frame1));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src1, N));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	w = codec_gzip_writer(io_heapwriter(&frame2));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src2, N));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	/* Concatenate both gzip members into one buffer */
	combined = VBUF_NEW(VBUF_LEN(frame1) + VBUF_LEN(frame2));
	T_CHECK(combined != NULL);
	VBUF_APPEND(combined, VBUF_DATA(frame1), VBUF_LEN(frame1));
	VBUF_APPEND(combined, VBUF_DATA(frame2), VBUF_LEN(frame2));
	T_CHECK(!VBUF_HAS_OOM(combined));
	VBUF_FREE(frame1);
	VBUF_FREE(frame2);

	r = codec_gzip_reader(
		io_memreader(VBUF_DATA(combined), VBUF_LEN(combined)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N * 2));
	T_EXPECT_EQ(stream_close(r), 0);
	r = NULL;

	T_EXPECT_MEMEQ(out, src1, N);
	T_EXPECT_MEMEQ(out + N, src2, N);
	VBUF_FREE(combined);
}

T_DECLARE_CASE(codec_gzip_crc_error)
{
	enum { N = 512 };
	uint_least8_t src[N];
	uint_least8_t dummy[N];
	struct vbuffer *compressed = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 7U + 5U) & 0xffU);
	}
	compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);

	w = codec_gzip_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	T_CHECK(compressed != NULL && VBUF_LEN(compressed) >= 8);
	/* Flip a bit in the CRC-32 field (last 8 bytes, first 4 = CRC) */
	((unsigned char *)VBUF_DATA(compressed))[VBUF_LEN(compressed) - 8] ^=
		0x01;

	r = codec_gzip_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	/* Read all body data, then probe for trailer to trigger validation */
	(void)stream_read(r, dummy, &(size_t){ sizeof(dummy) });
	{
		unsigned char probe[1];
		size_t n = sizeof(probe);
		(void)stream_read(r, probe, &n);
	}
	const int err = stream_close(r);
	r = NULL;
	VBUF_FREE(compressed);
	T_EXPECT(err != 0);
}

T_DECLARE_CASE(codec_gzip_flush_multiframe)
{
	enum { N1 = 4096, N2 = 4096 };
	uint_least8_t src1[N1], src2[N2];
	uint_least8_t out[N1 + N2];
	struct vbuffer *compressed = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N1; ++i) {
		src1[i] = (uint_least8_t)((i * 23U) & 0xffU);
	}
	for (i = 0; i < N2; ++i) {
		src2[i] = (uint_least8_t)((i * 31U + 9U) & 0xffU);
	}
	compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);

	/* Write two frames via flush boundary */
	w = codec_gzip_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src1, N1));
	T_EXPECT_EQ(stream_flush(w), 0);
	T_EXPECT(stream_write_all(w, src2, N2));
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	T_CHECK(compressed != NULL);
	T_EXPECT(VBUF_LEN(compressed) > 0);

	/* Verify two gzip magic headers in the compressed output */
	{
		const unsigned char *data = VBUF_DATA(compressed);
		const size_t len = VBUF_LEN(compressed);
		T_EXPECT(len >= 20);
		T_EXPECT(data[0] == 0x1f && data[1] == 0x8b);
		/* Scan for second gzip header after the first member */
		size_t found = 0;
		for (size_t j = 4; j + 1 < len; ++j) {
			if (data[j] == 0x1f && data[j + 1] == 0x8b) {
				found = j;
				break;
			}
		}
		T_EXPECT(found > 0);
	}

	/* Read back with gzip_reader (supports multi-member) */
	r = codec_gzip_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N1 + N2));
	T_EXPECT_EQ(stream_close(r), 0);
	r = NULL;

	T_EXPECT_MEMEQ(out, src1, N1);
	T_EXPECT_MEMEQ(out + N1, src2, N2);
	VBUF_FREE(compressed);
}

T_DECLARE_CASE(codec_gzip_flush_empty)
{
	enum { N = 4096 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	struct vbuffer *compressed = NULL;
	struct stream *w = NULL;
	struct stream *r = NULL;
	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 41U + 13U) & 0xffU);
	}
	compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);

	/* Flush then close without writing more data should produce one member */
	w = codec_gzip_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N));
	T_EXPECT_EQ(stream_flush(w), 0);
	T_EXPECT_EQ(stream_close(w), 0);
	w = NULL;

	T_CHECK(compressed != NULL);
	T_EXPECT(VBUF_LEN(compressed) > 0);

	r = codec_gzip_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	r = NULL;

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(compressed);
}

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, codec_null_base);
	T_RUN_CASE(t, codec_zlib_roundtrip);
	T_RUN_CASE(t, codec_deflate_roundtrip);
	T_RUN_CASE(t, codec_gzip_roundtrip);
	T_RUN_CASE(t, codec_gzip_multiframe);
	T_RUN_CASE(t, codec_gzip_crc_error);
	T_RUN_CASE(t, codec_gzip_flush_multiframe);
	T_RUN_CASE(t, codec_gzip_flush_empty);

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
