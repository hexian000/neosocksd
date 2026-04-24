/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sync/dispatcher.h"
#include "sync/task.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <threads.h>

#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status = (expr);                                     \
		(void)status;                                                  \
		assert(status == thrd_success);                                \
	} while (0)

#define INLINE_TASK_CAPACITY 16

struct task_item {
	struct task task;
	struct task_item *next;
};

struct dispatcher {
	mtx_t mu;
	cnd_t cond;
	struct {
		struct task_item *head, *tail;
	} queue;
	/* Inline pool for task items; pool_free is the head of the free list */
	struct task_item *pool_free;
	struct task_item pool[INLINE_TASK_CAPACITY];
	bool exit_flag : 1;
};

static bool dequeue(struct dispatcher *d, struct task *task, const bool wait)
{
	THRD_ASSERT(mtx_lock(&d->mu));
	for (;;) {
		struct task_item *restrict item = d->queue.head;
		if (item != NULL) {
			d->queue.head = item->next;
			if (d->queue.tail == item) {
				d->queue.tail = NULL;
			}
			*task = item->task;
			/* Return pool items to the free list; free heap-allocated items
			 * after releasing the lock to avoid holding it during free() */
			struct task_item *to_free;
			if (item >= d->pool &&
			    item < d->pool + INLINE_TASK_CAPACITY) {
				item->next = d->pool_free;
				d->pool_free = item;
				to_free = NULL;
			} else {
				to_free = item;
			}
			THRD_ASSERT(mtx_unlock(&d->mu));
			free(to_free);
			return true;
		}
		if (!wait || d->exit_flag) {
			THRD_ASSERT(mtx_unlock(&d->mu));
			return false;
		}
		THRD_ASSERT(cnd_wait(&d->cond, &d->mu));
	}
}

static bool enqueue(struct dispatcher *d, const struct task *task)
{
	/* Try the inline pool first (under the mutex) */
	THRD_ASSERT(mtx_lock(&d->mu));
	if (d->exit_flag) {
		THRD_ASSERT(mtx_unlock(&d->mu));
		return false;
	}
	struct task_item *new_item;
	if (d->pool_free != NULL) {
		new_item = d->pool_free;
		d->pool_free = new_item->next;
	} else {
		/* Pool exhausted: release lock while allocating to avoid
		 * holding it during a potentially slow heap operation */
		THRD_ASSERT(mtx_unlock(&d->mu));
		new_item = malloc(sizeof(struct task_item));
		if (new_item == NULL) {
			return false;
		}
		THRD_ASSERT(mtx_lock(&d->mu));
		if (d->exit_flag) {
			THRD_ASSERT(mtx_unlock(&d->mu));
			free(new_item);
			return false;
		}
	}
	*new_item = (struct task_item){ *task, NULL };
	struct task_item *restrict tail = d->queue.tail;
	if (tail != NULL) {
		tail->next = new_item;
	} else {
		d->queue.head = new_item;
	}
	d->queue.tail = new_item;
	THRD_ASSERT(cnd_signal(&d->cond));
	THRD_ASSERT(mtx_unlock(&d->mu));
	return true;
}

struct dispatcher *dispatcher_create(void)
{
	struct dispatcher *restrict d = malloc(sizeof(struct dispatcher));
	if (d == NULL) {
		return NULL;
	}
	d->exit_flag = false;
	d->queue.head = NULL;
	d->queue.tail = NULL;
	for (int i = 0; i < INLINE_TASK_CAPACITY - 1; i++) {
		d->pool[i].next = &d->pool[i + 1];
	}
	d->pool[INLINE_TASK_CAPACITY - 1].next = NULL;
	d->pool_free = &d->pool[0];
	if (mtx_init(&d->mu, mtx_plain) != thrd_success) {
		free(d);
		return NULL;
	}
	if (cnd_init(&d->cond) != thrd_success) {
		mtx_destroy(&d->mu);
		free(d);
		return NULL;
	}
	return d;
}

bool dispatcher_invoke(struct dispatcher *d, const struct task task)
{
	return enqueue(d, &task);
}

void dispatcher_tick(struct dispatcher *d)
{
	struct task task;
	while (dequeue(d, &task, false)) {
		task.func(task.data);
	}
}

void dispatcher_join(struct dispatcher *d)
{
	/* Set exit flag first to prevent new tasks from being enqueued */
	THRD_ASSERT(mtx_lock(&d->mu));
	d->exit_flag = true;
	THRD_ASSERT(mtx_unlock(&d->mu));

	struct task task;
	while (dequeue(d, &task, false)) {
		task.func(task.data);
	}
	dispatcher_destroy(d);
}

void dispatcher_loop(struct dispatcher *d)
{
	struct task task;
	while (dequeue(d, &task, true)) {
		task.func(task.data);
	}
}

void dispatcher_break(struct dispatcher *d)
{
	THRD_ASSERT(mtx_lock(&d->mu));
	d->exit_flag = true;
	THRD_ASSERT(mtx_unlock(&d->mu));
	THRD_ASSERT(cnd_broadcast(&d->cond));
}

void dispatcher_destroy(struct dispatcher *d)
{
	/* Clean up remaining tasks; skip free() for inline pool items */
	struct task_item *item = d->queue.head;
	while (item != NULL) {
		struct task_item *next = item->next;
		if (item < d->pool || item >= d->pool + INLINE_TASK_CAPACITY) {
			free(item);
		}
		item = next;
	}
	cnd_destroy(&d->cond);
	mtx_destroy(&d->mu);
	free(d);
}
