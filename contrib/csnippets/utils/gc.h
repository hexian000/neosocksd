/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_GC_H
#define UTILS_GC_H

#include <stddef.h>

/**
 * @file gc.h
 * @brief Garbage collection utilities for reference-counted objects.
 * @details None of the APIs are thread-safe; add external synchronization
 * if objects are registered, referenced, or unreferenced from multiple
 * threads.
 */

struct gcbase;

/**
 * @brief Function pointer type for object finalizers.
 */
typedef void (*gc_finalizer)(struct gcbase *restrict);

/**
 * @brief Base structure for garbage-collected objects.
 */
struct gcbase {
	gc_finalizer finalize;
	struct gcbase *prev, *next;
	size_t refs;
};

/**
 * @brief Registers an object for garbage collection.
 * @details Registration takes the first reference: the object starts with a
 * refcount of 1, owned by the registrant, so a single gc_unref() from it
 * finalizes and frees the object.
 * @param obj The object to register; must point to the start of its own
 * heap allocation, as it is later freed directly via free().
 * @param finalizer The finalizer function, or NULL.
 */
void gc_register(struct gcbase *restrict obj, gc_finalizer finalizer);

/**
 * @brief Increments the reference count of an object.
 * @param obj The object to reference.
 */
void gc_ref(struct gcbase *restrict obj);

/**
 * @brief Decrements the reference count of an object.
 * @param obj The object to unreference.
 */
void gc_unref(struct gcbase *restrict obj);

/**
 * @brief Finalizes all remaining garbage-collected objects.
 * @details Disregards refs: every registered object is finalized and
 * freed unconditionally, even those with outstanding references. This
 * is intended for unconditional teardown (e.g. at process exit), not
 * as a refcount-aware "collect what's now unreachable" pass; callers
 * still holding a reference to a finalized object are left with a
 * dangling pointer.
 *
 * Teardown is two-phase: every registered object's finalizer runs before
 * any of them is freed. A finalizer may therefore release the objects it
 * owns with gc_unref() whatever order they were registered in; gc_ref()
 * and gc_unref() on an object being torn down are no-ops, and each such
 * object is finalized exactly once. An object a finalizer registers is
 * torn down too, before the call returns.
 * @return The number of objects finalized.
 */
size_t gc_finalizeall(void);

#endif /* UTILS_GC_H */
