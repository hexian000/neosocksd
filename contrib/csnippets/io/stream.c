#include "stream.h"
#include <stddef.h>

int stream_direct_read(struct stream *s, const void **buf, size_t *len)
{
	return s->vftable->direct_read(s, buf, len);
}

int stream_read(struct stream *s, void *buf, size_t *len)
{
	const io_reader read = s->vftable->read;
	if (read != NULL) {
		return read(s, buf, len);
	}
	const io_direct_reader direct_read = s->vftable->direct_read;
	int err = 0;
	size_t nread = 0;
	unsigned char *dst = buf;
	size_t dstsize = *len;
	while (dstsize > 0 && err == 0) {
		const void *src;
		size_t n = dstsize;
		err = direct_read(s, &src, &n);
		if (n == 0) {
			break;
		}
		memcpy(dst, src, n);
		dst += n;
		dstsize -= n;
		nread += n;
	}
	*len = nread;
	return err;
}

int stream_write(struct stream *s, const void *buf, size_t *len)
{
	return s->vftable->write(s, buf, len);
}

int stream_flush(struct stream *s)
{
	const io_flusher flush = s->vftable->flush;
	if (flush == NULL) {
		return 0;
	}
	return flush(s);
}

int stream_close(struct stream *s)
{
	const io_closer close = s->vftable->close;
	if (close == NULL) {
		free(s);
		return 0;
	}
	return close(s);
}

int stream_copy(
	struct stream *dst, struct stream *src, void *buf, const size_t bufsize)
{
	int err = 0;
	size_t len;
	do {
		len = bufsize;
		const int srcerr = stream_read(src, buf, &len);
		const int dsterr = stream_write(dst, buf, &len);
		if (err == 0) {
			err = srcerr;
		}
		if (err == 0) {
			err = dsterr;
		}
	} while (len > 0 && err == 0);
	const int srcerr = stream_close(src);
	if (err == 0) {
		err = srcerr;
	}
	const int dsterr = stream_close(dst);
	if (err == 0) {
		err = dsterr;
	}
	return err;
}
