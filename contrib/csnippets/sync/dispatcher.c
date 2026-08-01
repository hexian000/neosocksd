/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sync/dispatcher.h"

#include "sync/task.h"
#include "sync/thrd.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <threads.h>

struct dispatcher {
	mtx_t mu;
	/* Bounded ring buffer: head is the oldest task, count the number held */
	size_t capacity;
	size_t head;
	size_t count;
	struct task buf[];
};

static bool dequeue(struct dispatcher *d, struct task *task)
{
	THRD_ASSERT(mtx_lock(&d->mu));
	if (d->count == 0) {
		THRD_ASSERT(mtx_unlock(&d->mu));
		return false;
	}
	*task = d->buf[d->head];
	if (++d->head >= d->capacity) {
		d->head -= d->capacity;
	}
	d->count--;
	THRD_ASSERT(mtx_unlock(&d->mu));
	return true;
}

static bool enqueue(struct dispatcher *d, const struct task *task)
{
	THRD_ASSERT(mtx_lock(&d->mu));
	if (d->count == d->capacity) {
		THRD_ASSERT(mtx_unlock(&d->mu));
		return false;
	}
	size_t tail = d->head + d->count;
	if (tail >= d->capacity) {
		tail -= d->capacity;
	}
	d->buf[tail] = *task;
	d->count++;
	THRD_ASSERT(mtx_unlock(&d->mu));
	return true;
}

struct dispatcher *dispatcher_create(const size_t capacity)
{
	if (capacity == 0) {
		return NULL;
	}
	if (capacity >
	    (SIZE_MAX - sizeof(struct dispatcher)) / sizeof(struct task)) {
		return NULL;
	}
	struct dispatcher *restrict d = malloc(
		sizeof(struct dispatcher) + sizeof(struct task) * capacity);
	if (d == NULL) {
		return NULL;
	}
	d->capacity = capacity;
	d->head = 0;
	d->count = 0;
	if (mtx_init(&d->mu, mtx_plain) != thrd_success) {
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
	while (dequeue(d, &task)) {
		task.func(task.data);
	}
}

void dispatcher_join(struct dispatcher *d)
{
	struct task task;
	while (dequeue(d, &task)) {
		task.func(task.data);
	}
	dispatcher_destroy(d);
}

void dispatcher_destroy(struct dispatcher *d)
{
	/* Pending tasks are plain values; discarding the ring drops them */
	mtx_destroy(&d->mu);
	free(d);
}
