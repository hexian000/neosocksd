/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_IO_H
#define IO_IO_H

#include <stddef.h>
#include <stdio.h>

#define IO_BUFSIZE 4096

typedef int (*io_direct_reader)(void *, const void **buf, size_t *len);
typedef int (*io_reader)(void *, void *buf, size_t *len);
typedef int (*io_writer)(void *, const void *buf, size_t *len);
typedef int (*io_flusher)(void *);
typedef int (*io_closer)(void *);

#endif /* IO_IO_H */
