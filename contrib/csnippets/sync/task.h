/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_TASK_H
#define SYNC_TASK_H

struct task {
	void (*func)(void *);
	void *data;
};

#endif /* SYNC_TASK_H */
