/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * codec_test - white-box unit tests for proto/codec.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   proto/codec.c    module under test
 * Leaf libraries: csnippets (io/stream, utils/buffer), miniz.
 *
 * codec.c has no stateful collaborators, so this test links no other module
 * sources and the mock section below is empty.
 */

#include "codec.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "meta/arraysize.h"
#include "miniz.h"
#include "utils/buffer.h"
#include "utils/testing.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - codec.c has no stateful collaborators; nothing to mock.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * fuzz - randomized codec inputs are exercised by main_test (fuzz_inflate,
 * fuzz_zlib, fuzz_gzip); none here.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - deterministic round-trip and malformed-input cases.
 * ---------------------------------------------------------------------- */

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

static int write_tempfile(char *restrict tmpl, const void *content, size_t len)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	if ((size_t)write(fd, content, len) != len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	return close(fd);
}

static bool read_lua_source(
	const char *restrict path, char *restrict out, const size_t cap,
	size_t *restrict out_len)
{
	struct stream *restrict r = codec_lua_reader(path);
	if (r == NULL) {
		return false;
	}
	size_t total = 0;
	for (;;) {
		size_t n = cap - total;
		if (n == 0 || stream_read(r, out + total, &n) != 0) {
			stream_close(r);
			return false;
		}
		if (n == 0) {
			break;
		}
		total += n;
	}
	*out_len = total;
	return stream_close(r) == 0;
}

/*
 * Regression: a real shebang line ("#!/usr/bin/env lua\n") is longer than
 * the reader's old 4-byte BOM-detection peek, so lua_skip_shebang never
 * saw the newline within that window and the raw "#!/u" bytes were
 * emitted as if they were Lua source.
 */
T_DECLARE_CASE(codec_lua_reader_strips_shebang)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	static const char content[] =
		"#!/usr/bin/env lua --with-a-fairly-long-set-of-flags-here\n"
		"return 1\n";
	T_CHECK(write_tempfile(path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	(void)unlink(path);
}

/*
 * Regression: a UTF-8 BOM followed immediately by "#!" leaves only 1 byte
 * of the 4-byte peek for the shebang-prefix check, so lua_skip_shebang
 * used to give up before it could even confirm a shebang was present.
 */
T_DECLARE_CASE(codec_lua_reader_strips_bom_and_shebang)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	static const char content[] = "\xEF\xBB\xBF"
				      "#!/usr/bin/env lua\n"
				      "return 1\n";
	T_CHECK(write_tempfile(path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	(void)unlink(path);
}

T_DECLARE_CASE(codec_lua_reader_strips_bom_only)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	static const char content[] = "\xEF\xBB\xBF"
				      "return 1\n";
	T_CHECK(write_tempfile(path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	(void)unlink(path);
}

/* Regression: the first read (the BOM peek) must not return more bytes than
 * the caller requested; a sub-LUA_PEEK_SIZE first stream_read() on a BOM-less
 * file would otherwise over-copy LUA_PEEK_SIZE bytes into the smaller buffer. */
T_DECLARE_CASE(codec_lua_reader_small_first_read)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	static const char content[] = "return 1234\n"; /* no BOM, no shebang */
	T_CHECK(write_tempfile(path, content, sizeof(content) - 1) == 0);

	struct stream *restrict r = codec_lua_reader(path);
	T_CHECK(r != NULL);

	/* exact-sized heap buffer (< LUA_PEEK_SIZE) so ASan flags any over-copy */
	enum { SMALL = 4 };
	unsigned char *const buf = malloc(SMALL);
	T_CHECK(buf != NULL);
	size_t n = SMALL;
	T_EXPECT_EQ(stream_read(r, buf, &n), 0);
	T_EXPECT(n > 0);
	T_EXPECT(
		n <=
		(size_t)SMALL); /* direct_read must not exceed the request */
	T_EXPECT_MEMEQ(buf, content, n);

	free(buf);
	(void)stream_close(r);
	(void)unlink(path);
}

/*
 * codec_lua_reader peeks two bytes and, on the gzip magic, wraps the base in
 * codec_gzip_reader before the BOM/shebang stripper. Every other reader case
 * feeds plaintext, and every other caller uses plaintext/"-"/nonexistent
 * paths, so the documented "auto-detects gzip" feature -- loading a .lua.gz
 * ruleset, including the compound path where the shebang is stripped by
 * reading *through* the decompressor -- was entirely unverified.
 */
T_DECLARE_CASE(codec_lua_reader_gunzips_source)
{
	static const char content[] = "#!/usr/bin/env lua\n"
				      "return 1\n";
	struct vbuffer *gz = VBUF_NEW(64);
	T_CHECK(gz != NULL);
	{
		struct stream *w = codec_gzip_writer(io_heapwriter(&gz));
		T_CHECK(w != NULL);
		T_EXPECT(stream_write_all(w, content, sizeof(content) - 1));
		T_EXPECT_EQ(stream_close(w), 0);
	}
	T_CHECK(gz != NULL);
	/* the magic the detector keys on */
	T_CHECK(VBUF_LEN(gz) > 2);
	{
		const unsigned char *const magic = VBUF_DATA(gz);
		T_EXPECT_EQ(magic[0], 0x1f);
		T_EXPECT_EQ(magic[1], 0x8b);
	}

	char path[] = "/tmp/codec_test_XXXXXX";
	T_CHECK(write_tempfile(path, VBUF_DATA(gz), VBUF_LEN(gz)) == 0);
	VBUF_FREE(gz);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	/* decompressed, and the shebang stripped through the decompressor */
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	(void)unlink(path);
}

T_DECLARE_CASE(codec_lua_reader_passthrough_plain_file)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	static const char content[] = "return 1\n";
	T_CHECK(write_tempfile(path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, sizeof(content) - 1);
	T_EXPECT_MEMEQ(out, content, len);

	(void)unlink(path);
}

/* A file that is nothing but a UTF-8 BOM is a valid (empty) chunk: the BOM is
 * stripped and no source bytes are emitted. Exercises the peek window filling
 * to exactly the BOM length and then hitting EOF. */
T_DECLARE_CASE(codec_lua_reader_bom_only_no_content)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	static const char content[] =
		"\xEF\xBB\xBF"; /* UTF-8 BOM, nothing after */
	T_CHECK(write_tempfile(path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len = 12345;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, (size_t)0);

	(void)unlink(path);
}

/* An empty source yields an empty chunk cleanly: a zero-length first read is
 * EOF, not a state the reader must recover from. */
T_DECLARE_CASE(codec_lua_reader_empty_stream)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	T_CHECK(write_tempfile(path, "", 0) == 0);

	char out[128];
	size_t len = 12345;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, (size_t)0);

	(void)unlink(path);
}

/*
 * Regression: a shebang line longer than the peek window whose terminating
 * newline falls exactly on a direct_read chunk boundary (offset == n). The
 * bufreader serves the file in IO_BUFSIZE chunks after the 8-byte peek, so a
 * shebang line of exactly IO_BUFSIZE bytes puts its '\n' as the last byte of
 * the first post-peek chunk. lua_direct_read's continuation loop then flips to
 * LUA_PASSTHROUGH but re-iterates; if it re-runs lua_skip_shebang on the next
 * chunk of real source it strips that chunk's first line. The whole source
 * ("return 42\n" + "return 7\n") must survive.
 */
T_DECLARE_CASE(codec_lua_reader_shebang_newline_on_chunk_boundary)
{
	char path[] = "/tmp/codec_test_XXXXXX";
	enum { SHEBANG_LEN = IO_BUFSIZE };
	static const char source[] = "return 42\nreturn 7\n";
	const size_t total = SHEBANG_LEN + sizeof(source) - 1;
	char *const content = malloc(total);
	T_CHECK(content != NULL);
	/* "#!" + filler + '\n', exactly IO_BUFSIZE bytes. */
	content[0] = '#';
	content[1] = '!';
	memset(content + 2, 'x', SHEBANG_LEN - 3);
	content[SHEBANG_LEN - 1] = '\n';
	memcpy(content + SHEBANG_LEN, source, sizeof(source) - 1);
	const int rc = write_tempfile(path, content, total);
	free(content);
	T_CHECK(rc == 0);

	/* Read with a buffer larger than IO_BUFSIZE so the first post-peek chunk
	 * spans the whole 4088-byte buffered remainder up to the boundary. */
	char out[2 * IO_BUFSIZE];
	size_t len;
	T_EXPECT(read_lua_source(path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, sizeof(source) - 1);
	T_EXPECT_MEMEQ(out, source, len);

	(void)unlink(path);
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

/*
 * The decompressors reset their TINFL_LZ_DICT_SIZE (32 KiB) ring only once it
 * is both completely full and completely drained. No other case decompresses
 * more than 16 KiB in one run, so that reset -- and LZ back-references
 * resolving across it, the subtlest correctness point in the module -- never
 * ran, even though it is on the hot path for any HTTP body or gzip ruleset
 * over 32 KiB decompressed. Read back in small chunks so the ring fills and
 * wraps repeatedly.
 */
T_DECLARE_CASE(codec_decompress_ring_wraparound)
{
	enum { N = 100000 }; /* > TINFL_LZ_DICT_SIZE */
	static const struct {
		const char *name;
		struct stream *(*writer)(struct stream *);
		struct stream *(*reader)(struct stream *);
	} variants[] = {
		{ "zlib", codec_zlib_writer, codec_zlib_reader },
		{ "deflate", codec_deflate_writer, codec_inflate_reader },
		{ "gzip", codec_gzip_writer, codec_gzip_reader },
	};
	uint_least8_t *const src = malloc(N);
	uint_least8_t *const out = malloc(N);
	T_CHECK(src != NULL);
	T_CHECK(out != NULL);
	/* Moderately compressible: a repeating motif perturbed periodically, so
	 * the encoder emits real back-references (some reaching across the ring
	 * boundary) rather than one long run. */
	for (size_t i = 0; i < (size_t)N; ++i) {
		src[i] = (uint_least8_t)((i % 251U) ^ ((i / 1024U) & 0x0fU));
	}

	for (size_t v = 0; v < ARRAY_SIZE(variants); v++) {
		struct vbuffer *compressed = VBUF_NEW(64);
		T_CHECK(compressed != NULL);

		struct stream *w =
			variants[v].writer(io_heapwriter(&compressed));
		T_CHECK(w != NULL);
		T_EXPECT(stream_write_all(w, src, N));
		T_EXPECT_EQ(stream_close(w), 0);
		T_CHECK(compressed != NULL);
		/* it really did compress, so back-references are in play */
		T_EXPECT(VBUF_LEN(compressed) < (size_t)N);

		struct stream *r = variants[v].reader(io_memreader(
			VBUF_DATA(compressed), VBUF_LEN(compressed)));
		T_CHECK(r != NULL);
		memset(out, 0, N);
		for (size_t off = 0; off < (size_t)N;) {
			size_t n = (size_t)N - off;
			if (n > 1000) {
				n = 1000;
			}
			T_EXPECT(stream_read_exact(r, out + off, n));
			off += n;
		}
		T_EXPECT_EQ(stream_close(r), 0);
		T_EXPECT_MEMEQ(out, src, N);
		VBUF_FREE(compressed);
	}

	free(src);
	free(out);
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
	T_EXPECT(stream_read_exact(r, out, (size_t)N * 2));
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

/* gzip header flag bits (RFC 1952), mirrored from codec.c */
enum {
	GZIP_FHCRC = 1 << 1,
	GZIP_FEXTRA = 1 << 2,
	GZIP_FNAME = 1 << 3,
	GZIP_FCOMMENT = 1 << 4,
};

/* Compress src via the gzip writer and return the raw member bytes. */
static struct vbuffer *gzip_make_member(const void *src, const size_t srclen)
{
	struct vbuffer *compressed = VBUF_NEW(64);
	if (compressed == NULL) {
		return NULL;
	}
	struct stream *w = codec_gzip_writer(io_heapwriter(&compressed));
	if (w == NULL) {
		VBUF_FREE(compressed);
		return NULL;
	}
	if (!stream_write_all(w, src, srclen) || stream_close(w) != 0) {
		VBUF_FREE(compressed);
		return NULL;
	}
	return compressed;
}

/*
 * Build a gzip member that carries the optional FEXTRA, FNAME, FCOMMENT and
 * FHCRC header fields. The miniz writer never emits these, so the reader's
 * optional-field parser is only reachable from hand-crafted input. When
 * corrupt_hcrc is true the stored header CRC-16 is flipped to drive the
 * mismatch path.
 */
static struct vbuffer *
gzip_with_opt_headers(const void *src, const size_t srclen, bool corrupt_hcrc)
{
	struct vbuffer *plain = gzip_make_member(src, srclen);
	if (plain == NULL) {
		return NULL;
	}
	const unsigned char *p = VBUF_DATA(plain);
	const size_t plen = VBUF_LEN(plain);
	if (plen < 10) {
		VBUF_FREE(plain);
		return NULL;
	}

	static const unsigned char extra[] = { 'A', 'B', 'C', 'D' };
	static const unsigned char name[] = { 'n', 'a', 'm', 'e', 0x00 };
	static const unsigned char comment[] = { 'h', 'i', 0x00 };

	struct vbuffer *out = VBUF_NEW(plen + 32);
	if (out == NULL) {
		VBUF_FREE(plain);
		return NULL;
	}
	/* fixed 10-byte header with optional-field flags set */
	unsigned char hdr[10];
	memcpy(hdr, p, sizeof(hdr));
	hdr[3] = GZIP_FEXTRA | GZIP_FNAME | GZIP_FCOMMENT | GZIP_FHCRC;
	VBUF_APPEND(out, hdr, sizeof(hdr));
	/* FEXTRA: 2-byte little-endian length then the extra bytes */
	const unsigned char xlen[2] = { (unsigned char)sizeof(extra), 0x00 };
	VBUF_APPEND(out, xlen, sizeof(xlen));
	VBUF_APPEND(out, extra, sizeof(extra));
	/* FNAME and FCOMMENT: NUL-terminated strings */
	VBUF_APPEND(out, name, sizeof(name));
	VBUF_APPEND(out, comment, sizeof(comment));
	/* FHCRC: low 16 bits of the CRC-32 over all preceding header bytes */
	const mz_ulong crc =
		mz_crc32(MZ_CRC32_INIT, VBUF_DATA(out), VBUF_LEN(out));
	unsigned char hcrc[2] = { (unsigned char)(crc & 0xffu),
				  (unsigned char)((crc >> 8) & 0xffu) };
	if (corrupt_hcrc) {
		hcrc[0] ^= 0xffu;
	}
	VBUF_APPEND(out, hcrc, sizeof(hcrc));
	/* DEFLATE body and trailer copied verbatim from the plain member */
	VBUF_APPEND(out, p + 10, plen - 10);

	const bool ok = !VBUF_HAS_OOM(out);
	VBUF_FREE(plain);
	if (!ok) {
		VBUF_FREE(out);
		return NULL;
	}
	return out;
}

T_DECLARE_CASE(codec_gzip_optional_headers)
{
	enum { N = 2048 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 19U + 7U) & 0xffU);
	}

	struct vbuffer *g = gzip_with_opt_headers(src, N, false);
	T_CHECK(g != NULL);

	struct stream *r =
		codec_gzip_reader(io_memreader(VBUF_DATA(g), VBUF_LEN(g)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(g);
}

/* Regression: an empty FNAME immediately after FEXTRA. The header parser must
 * read the FNAME terminator from srcbuf, not the stale once-per-iteration byte
 * (the nonzero OS byte) carried through the FEXTRA fallthrough. */
T_DECLARE_CASE(codec_gzip_empty_fname_after_fextra)
{
	enum { N = 2048 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 23U + 5U) & 0xffU);
	}

	struct vbuffer *plain = gzip_make_member(src, N);
	T_CHECK(plain != NULL);
	const unsigned char *p = VBUF_DATA(plain);
	const size_t plen = VBUF_LEN(plain);
	T_CHECK(plen >= 10);

	static const unsigned char extra[] = { 'A', 'B', 'C', 'D' };
	struct vbuffer *g = VBUF_NEW(plen + 8);
	T_CHECK(g != NULL);
	unsigned char hdr[10];
	memcpy(hdr, p, sizeof(hdr));
	hdr[3] = GZIP_FEXTRA | GZIP_FNAME;
	hdr[9] = 0xff; /* OS byte: the (nonzero) stale byte reached at FNAME */
	VBUF_APPEND(g, hdr, sizeof(hdr));
	const unsigned char xlen[2] = { (unsigned char)sizeof(extra), 0x00 };
	VBUF_APPEND(g, xlen, sizeof(xlen));
	VBUF_APPEND(g, extra, sizeof(extra));
	static const unsigned char empty_name[] = { 0x00 }; /* empty FNAME */
	VBUF_APPEND(g, empty_name, sizeof(empty_name));
	VBUF_APPEND(g, p + 10, plen - 10); /* deflate body + trailer */
	T_CHECK(!VBUF_HAS_OOM(g));
	VBUF_FREE(plain);

	struct stream *r =
		codec_gzip_reader(io_memreader(VBUF_DATA(g), VBUF_LEN(g)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(g);
}

/* Regression: a full flush on a zlib/deflate writer must complete instead of
 * looping forever (TDEFL_FULL_FLUSH never reaches TDEFL_STATUS_DONE), and the
 * stream must still decode correctly after the flush and subsequent writes. */
T_DECLARE_CASE(codec_zlib_flush_then_continue)
{
	enum { N = 4096 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 37U) & 0xffU);
	}

	struct vbuffer *compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);
	struct stream *w = codec_zlib_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N / 2));
	T_EXPECT_EQ(stream_flush(w), 0);
	T_EXPECT(stream_write_all(w, src + (N / 2), N - (N / 2)));
	T_EXPECT_EQ(stream_close(w), 0);

	struct stream *r = codec_zlib_reader(
		io_memreader(VBUF_DATA(compressed), VBUF_LEN(compressed)));
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT_EQ(stream_close(r), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(compressed);
}

/* Corrupt-input coverage for the zlib reader (parallel to the gzip cases): an
 * invalid zlib header and a truncated stream must both fail the read. */
T_DECLARE_CASE(codec_zlib_corrupt_input_fails)
{
	enum { N = 1024 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 11U + 3U) & 0xffU);
	}

	struct vbuffer *compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);
	struct stream *w = codec_zlib_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(compressed != NULL && VBUF_LEN(compressed) >= 10);

	/* corrupt the zlib header (byte 0 holds CMF) */
	{
		unsigned char *d = VBUF_DATA(compressed);
		const unsigned char saved = d[0];
		d[0] ^= 0xffu;
		struct stream *r = codec_zlib_reader(
			io_memreader(d, VBUF_LEN(compressed)));
		if (r != NULL) {
			T_EXPECT(!stream_read_exact(r, out, N));
			(void)stream_close(r);
		}
		d[0] = saved;
	}
	/* truncated stream: only the first few bytes */
	{
		struct stream *r = codec_zlib_reader(
			io_memreader(VBUF_DATA(compressed), 5));
		if (r != NULL) {
			T_EXPECT(!stream_read_exact(r, out, N));
			(void)stream_close(r);
		}
	}
	VBUF_FREE(compressed);
}

/* codec_zlib_reader validates the trailing adler-32 (miniz enforces it via
 * TINFL_FLAG_PARSE_ZLIB_HEADER); flipping it must make the read/close fail. */
T_DECLARE_CASE(codec_zlib_adler32_mismatch)
{
	enum { N = 1024 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 11U + 3U) & 0xffU);
	}

	struct vbuffer *compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);
	struct stream *w = codec_zlib_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(compressed != NULL && VBUF_LEN(compressed) >= 6);

	/* the adler-32 is the last 4 bytes; flip one so it no longer matches */
	unsigned char *d = VBUF_DATA(compressed);
	const size_t len = VBUF_LEN(compressed);
	d[len - 1] ^= 0xffu;
	struct stream *r = codec_zlib_reader(io_memreader(d, len));
	T_CHECK(r != NULL);
	/* Read to EOF: the mismatch is reported once all output is consumed
	 * and the trailer is validated, as a real consumer draining the stream
	 * would observe. */
	bool read_failed = false;
	for (;;) {
		size_t n = sizeof(out);
		const int rret = stream_read(r, out, &n);
		if (rret != 0) {
			read_failed = true;
			break;
		}
		if (n == 0) {
			break;
		}
	}
	const int cret = stream_close(r);
	T_EXPECT(read_failed || cret != 0);
	VBUF_FREE(compressed);
}

/* A caller that reads exactly the decompressed length and then closes (without
 * a trailing EOF read) must still see a corrupt adler-32: inflate_close()
 * surfaces the decode status, mirroring the gzip reader. */
T_DECLARE_CASE(codec_zlib_adler32_mismatch_surfaced_at_close)
{
	enum { N = 1024 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 11U + 3U) & 0xffU);
	}

	struct vbuffer *compressed = VBUF_NEW(64);
	T_CHECK(compressed != NULL);
	struct stream *w = codec_zlib_writer(io_heapwriter(&compressed));
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, src, N));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(compressed != NULL && VBUF_LEN(compressed) >= 6);

	unsigned char *d = VBUF_DATA(compressed);
	const size_t len = VBUF_LEN(compressed);
	d[len - 1] ^= 0xffu;
	struct stream *r = codec_zlib_reader(io_memreader(d, len));
	T_CHECK(r != NULL);
	/* read exactly the decompressed length, then close without a final read */
	T_EXPECT(stream_read_exact(r, out, N));
	T_EXPECT(stream_close(r) != 0);
	VBUF_FREE(compressed);
}

T_DECLARE_CASE(codec_gzip_hcrc_mismatch)
{
	enum { N = 256 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 29U + 3U) & 0xffU);
	}

	struct vbuffer *g = gzip_with_opt_headers(src, N, true);
	T_CHECK(g != NULL);

	struct stream *r =
		codec_gzip_reader(io_memreader(VBUF_DATA(g), VBUF_LEN(g)));
	T_CHECK(r != NULL);
	/* The corrupt header CRC must make the read fail. */
	size_t n = sizeof(out);
	const int rret = stream_read(r, out, &n);
	const int cret = stream_close(r);
	T_EXPECT(rret != 0 || cret != 0);
	VBUF_FREE(g);
}

T_DECLARE_CASE(codec_gzip_bad_magic)
{
	/* A 10-byte header with an invalid magic must be rejected. */
	static const unsigned char bad[] = {
		0x1f, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	};
	struct stream *r = codec_gzip_reader(io_memreader(bad, sizeof(bad)));
	T_CHECK(r != NULL);
	unsigned char out[16];
	size_t n = sizeof(out);
	const int rret = stream_read(r, out, &n);
	const int cret = stream_close(r);
	T_EXPECT(rret != 0 || cret != 0);
}

/* Regression: a gzip header whose FEXTRA field ends exactly at end-of-input
 * with the FNAME flag set must not read past the source buffer. The FEXTRA_2
 * phase falls through to FNAME without re-checking the loop's srclen guard;
 * before the fix this over-read *srcbuf and underflowed srclen. The exact-size
 * heap buffer lets ASan catch any over-read. */
T_DECLARE_CASE(codec_gzip_truncated_after_fextra)
{
	static const unsigned char trunc[] = {
		/* 10-byte header, FLG = FEXTRA(0x04) | FNAME(0x08) */
		0x1f,
		0x8b,
		0x08,
		0x0c,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x03,
		/* XLEN = 4, a 4-byte extra field, then EOF (no name follows) */
		0x04,
		0x00,
		0xaa,
		0xbb,
		0xcc,
		0xdd,
	};
	unsigned char *const buf = malloc(sizeof(trunc));
	T_CHECK(buf != NULL);
	memcpy(buf, trunc, sizeof(trunc));
	struct stream *r = codec_gzip_reader(io_memreader(buf, sizeof(trunc)));
	T_CHECK(r != NULL);
	unsigned char out[16];
	size_t n = sizeof(out);
	const int rret = stream_read(r, out, &n);
	const int cret = stream_close(r);
	T_EXPECT(rret != 0 || cret != 0);
	free(buf);
}

/* -------------------------------------------------------------------------
 * bench - compress + decompress round-trip throughput (per message). Benches
 * run only when a name filter selects them (e.g. --run bench); a plain ctest
 * run skips them.
 * ---------------------------------------------------------------------- */

/* Fill a buffer with moderately compressible data. */
static void bench_fill(uint_least8_t *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		buf[i] = (uint_least8_t)(((i * 37U) ^ (i >> 3)) & 0x3fU);
	}
}

T_DECLARE_BENCH(bench_zlib_roundtrip)
{
	enum { N = 16384 };
	static uint_least8_t src[N];
	uint_least8_t out[N];
	bench_fill(src, N);

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		struct vbuffer *compressed = VBUF_NEW(64);
		T_CHECK(compressed != NULL);
		struct stream *w =
			codec_zlib_writer(io_heapwriter(&compressed));
		T_CHECK(w != NULL);
		T_CHECK(stream_write_all(w, src, N));
		T_CHECK(stream_close(w) == 0);
		struct stream *r = codec_zlib_reader(io_memreader(
			VBUF_DATA(compressed), VBUF_LEN(compressed)));
		T_CHECK(r != NULL);
		T_CHECK(stream_read_exact(r, out, N));
		T_CHECK(stream_close(r) == 0);
		VBUF_FREE(compressed);
	}
}

T_DECLARE_BENCH(bench_gzip_roundtrip)
{
	enum { N = 16384 };
	static uint_least8_t src[N];
	uint_least8_t out[N];
	bench_fill(src, N);

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		struct vbuffer *compressed = VBUF_NEW(64);
		T_CHECK(compressed != NULL);
		struct stream *w =
			codec_gzip_writer(io_heapwriter(&compressed));
		T_CHECK(w != NULL);
		T_CHECK(stream_write_all(w, src, N));
		T_CHECK(stream_close(w) == 0);
		struct stream *r = codec_gzip_reader(io_memreader(
			VBUF_DATA(compressed), VBUF_LEN(compressed)));
		T_CHECK(r != NULL);
		T_CHECK(stream_read_exact(r, out, N));
		T_CHECK(stream_close(r) == 0);
		VBUF_FREE(compressed);
	}
}

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(codec_lua_reader_strips_shebang),
	T_CASE(codec_lua_reader_strips_bom_and_shebang),
	T_CASE(codec_lua_reader_strips_bom_only),
	T_CASE(codec_lua_reader_small_first_read),
	T_CASE(codec_lua_reader_gunzips_source),
	T_CASE(codec_lua_reader_passthrough_plain_file),
	T_CASE(codec_lua_reader_bom_only_no_content),
	T_CASE(codec_lua_reader_empty_stream),
	T_CASE(codec_lua_reader_shebang_newline_on_chunk_boundary),
	T_CASE(codec_null_base),
	T_CASE(codec_zlib_roundtrip),
	T_CASE(codec_deflate_roundtrip),
	T_CASE(codec_gzip_roundtrip),
	T_CASE(codec_decompress_ring_wraparound),
	T_CASE(codec_gzip_multiframe),
	T_CASE(codec_gzip_crc_error),
	T_CASE(codec_gzip_flush_multiframe),
	T_CASE(codec_gzip_flush_empty),
	T_CASE(codec_gzip_optional_headers),
	T_CASE(codec_gzip_empty_fname_after_fextra),
	T_CASE(codec_zlib_flush_then_continue),
	T_CASE(codec_zlib_corrupt_input_fails),
	T_CASE(codec_zlib_adler32_mismatch),
	T_CASE(codec_zlib_adler32_mismatch_surfaced_at_close),
	T_CASE(codec_gzip_hcrc_mismatch),
	T_CASE(codec_gzip_bad_magic),
	T_CASE(codec_gzip_truncated_after_fextra),
	T_BENCH(bench_zlib_roundtrip),
	T_BENCH(bench_gzip_roundtrip),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
