/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "gc.h"

#include "utils/debug.h"

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

static void gc_finalize(struct gcbase *restrict obj)
{
	gc_unregister(obj);
	if (obj->finalize) {
		obj->finalize(obj);
	}
	free(obj);
}

void gc_ref(struct gcbase *restrict obj)
{
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
	size_t count = 0;
	for (struct gcbase *obj = gcroot; obj != NULL; obj = gcroot) {
		gc_finalize(obj);
		count++;
	}
	return count;
}
