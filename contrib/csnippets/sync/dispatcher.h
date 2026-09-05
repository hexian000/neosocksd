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
 * @brief Create a new dispatcher with the given queue capacity.
 *
 * @param capacity Maximum number of tasks the bounded queue can hold; must be
 *                 >= 1.
 * @return New dispatcher instance, or NULL if capacity is 0 or on failure.
 */
struct dispatcher *dispatcher_create(size_t capacity);

/**
 * @brief Enqueue a task for asynchronous execution (thread-safe).
 *
 * @param d Dispatcher instance.
 * @param task Task to enqueue.
 * @return true on success, false if the queue is full.
 */
bool dispatcher_invoke(struct dispatcher *d, struct task task);

/**
 * @brief Process all pending tasks until the queue is empty.
 *
 * Runs tasks until it finds the queue empty, including tasks invoked while it
 * runs, whether by a running task or by another thread. It does not wait for
 * tasks to arrive, but it returns only once the queue is empty: a task that
 * invokes itself again, or producers that invoke tasks at least as fast as
 * this thread runs them, keep it from returning.
 *
 * @param d Dispatcher instance.
 * @note Call periodically from main thread.
 */
void dispatcher_tick(struct dispatcher *d);

/**
 * @brief Shutdown dispatcher, process remaining tasks and cleanup.
 *
 * Processes pending tasks until the queue is empty, including tasks invoked
 * by the tasks it runs, then calls dispatcher_destroy().
 *
 * @param d Dispatcher instance.
 * @note Call from main thread. Pointer becomes invalid after return.
 * @warning No other threads may invoke tasks during or after this call.
 */
void dispatcher_join(struct dispatcher *d);

/**
 * @brief Destroy dispatcher and free its resources.
 *
 * Discards any pending tasks without executing them. Pending tasks are plain
 * values, so their data pointers are not released. In particular, a task
 * returned by packaged_task_bind() leaks its closure unless the queue is
 * drained with dispatcher_tick() or dispatcher_join() first.
 *
 * @param d Dispatcher instance.
 * @warning Ensure no other threads are accessing the dispatcher.
 */
void dispatcher_destroy(struct dispatcher *d);

/** @} */

#endif /* SYNC_DISPATCHER_H */
