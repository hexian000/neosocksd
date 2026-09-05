/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "gc.h"

#include "debug.h"

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

/* gc_finalizeall stores this in refs of every object it is tearing down, so a
 * gc_ref or gc_unref reaching such an object from a finalizer is recognized
 * and ignored; a live object's count stays below it (see gc_ref). */
#define GC_REFS_TEARDOWN SIZE_MAX

void gc_ref(struct gcbase *restrict obj)
{
	if (obj->refs == GC_REFS_TEARDOWN) {
		return;
	}
	ASSERT(obj->refs < GC_REFS_TEARDOWN - 1);
	obj->refs++;
}

void gc_unref(struct gcbase *restrict obj)
{
	if (obj->refs == GC_REFS_TEARDOWN) {
		return;
	}
	ASSERT(obj->refs > 0);
	obj->refs--;
	if (obj->refs == 0) {
		gc_finalize(obj);
	}
}

size_t gc_finalizeall(void)
{
	const size_t before = gc_finalized_total;
	/* An object registered by a finalizer lands on the emptied list and is
	 * torn down by the next round. */
	while (gcroot != NULL) {
		struct gcbase *const batch = gcroot;
		gcroot = NULL;
		/* Mark the whole batch before running any finalizer, so one that
		 * releases another object of the batch cannot finalize or free it
		 * early. */
		for (struct gcbase *obj = batch; obj != NULL; obj = obj->next) {
			obj->refs = GC_REFS_TEARDOWN;
		}
		/* Every object of the batch stays allocated until each finalizer
		 * in it has run. */
		for (struct gcbase *obj = batch; obj != NULL; obj = obj->next) {
			if (obj->finalize != NULL) {
				obj->finalize(obj);
			}
			gc_finalized_total++;
		}
		for (struct gcbase *obj = batch; obj != NULL;) {
			struct gcbase *const next = obj->next;
			free(obj);
			obj = next;
		}
	}
	/* the delta includes any object a finalizer finalized via gc_unref */
	return gc_finalized_total - before;
}
