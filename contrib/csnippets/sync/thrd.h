/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_THRD_H
#define SYNC_THRD_H

#include <assert.h>
#include <threads.h>

/* Assert that a C11 threads call returned thrd_success. The (void) cast keeps
 * the temporary live so the argument is still evaluated when assert() compiles
 * out under NDEBUG. */
#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status_ = (expr);                                    \
		(void)status_;                                                 \
		assert(status_ == thrd_success);                               \
	} while (0)

#endif /* SYNC_THRD_H */
