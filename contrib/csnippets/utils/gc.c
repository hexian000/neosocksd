/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "gc.h"

#include "utils/debug.h"

#include <stdint.h>
#include <stdlib.h>

static struct gcbase *gcroot = NULL;

void gc_register(struct gcbase *restrict obj, const gc_finalizer finalizer)
{
	*obj = (struct gcbase){
		.finalize = finalizer,
		.prev = NULL,
		.next = gcroot,
		.refs = 1,
	};
	if (gcroot != NULL) {
		gcroot->prev = obj;
	}
	gcroot = obj;
}

static void gc_unregister(struct gcbase *restrict obj)
{
	struct gcbase *restrict prev = obj->prev;
	struct gcbase *restrict next = obj->next;
	if (prev != NULL) {
		prev->next = next;
	} else {
		gcroot = next;
	}
	if (next != NULL) {
		next->prev = prev;
	}
}

/* Every object actually finalized bumps this, on both the gc_unref and the
 * gc_finalizeall path, so gc_finalizeall can count objects finalized as a side
 * effect of a finalizer (e.g. one that gc_unref()s another object to zero) via
 * the delta rather than only those it dequeued itself. */
static size_t gc_finalized_total;

static void gc_finalize(struct gcbase *restrict obj)
{
	gc_unregister(obj);
	if (obj->finalize != NULL) {
		obj->finalize(obj);
	}
	free(obj);
	gc_finalized_total++;
}

void gc_ref(struct gcbase *restrict obj)
{
	ASSERT(obj->refs < SIZE_MAX);
	obj->refs++;
}

void gc_unref(struct gcbase *restrict obj)
{
	ASSERT(obj->refs > 0);
	obj->refs--;
	if (obj->refs == 0) {
		gc_finalize(obj);
	}
}

size_t gc_finalizeall(void)
{
	const size_t before = gc_finalized_total;
	while (gcroot != NULL) {
		gc_finalize(gcroot);
	}
	/* the delta includes any object a finalizer finalized via gc_unref */
	return gc_finalized_total - before;
}
