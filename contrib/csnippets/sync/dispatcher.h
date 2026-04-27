/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_DISPATCHER_H
#define SYNC_DISPATCHER_H

#include "task.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup dispatcher
 * @brief Asynchronous task dispatcher with thread-safe queue.
 *
 * Main-thread usage: dispatcher_tick() to process pending tasks,
 * dispatcher_join() to drain and destroy.
 *
 * @{
 */

/**
 * @brief Opaque dispatcher structure.
 */
struct dispatcher;

/**
 * @brief Create a new dispatcher with the given inline pool capacity.
 * 
 * @param capacity Number of task items in the inline pool. 0 disables the
 *                 pool (all tasks are heap-allocated).
 * @return New dispatcher instance, or NULL on failure.
 */
struct dispatcher *dispatcher_create(size_t capacity);

/**
 * @brief Enqueue a task for asynchronous execution (thread-safe).
 * 
 * @param d Dispatcher instance.
 * @param task Task to enqueue.
 * @return true on success, false if allocation fails or dispatcher is shutting down.
 */
bool dispatcher_invoke(struct dispatcher *d, struct task task);

/**
 * @brief Process all pending tasks without blocking.
 * 
 * @param d Dispatcher instance.
 * @note Call periodically from main thread.
 */
void dispatcher_tick(struct dispatcher *d);

/**
 * @brief Shutdown dispatcher, process remaining tasks and cleanup.
 *
 * Processes all pending tasks, then calls dispatcher_destroy().
 *
 * @param d Dispatcher instance.
 * @note Call from main thread. Pointer becomes invalid after return.
 * @warning No other threads may invoke tasks during or after this call.
 */
void dispatcher_join(struct dispatcher *d);

/**
 * @brief Destroy dispatcher and free all resources.
 * 
 * Frees remaining tasks without executing them.
 * 
 * @param d Dispatcher instance.
 * @warning Ensure no other threads are accessing the dispatcher.
 */
void dispatcher_destroy(struct dispatcher *d);

/** @} */

#endif /* SYNC_DISPATCHER_H */
