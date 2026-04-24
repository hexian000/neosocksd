/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_DISPATCHER_H
#define SYNC_DISPATCHER_H

#include "task.h"

#include <stdbool.h>

/**
 * @defgroup dispatcher
 * @brief Asynchronous task dispatcher with thread-safe queue.
 * 
 * Two usage modes:
 * - Main thread: dispatcher_tick() + dispatcher_join()
 * - Worker thread: dispatcher_loop() + dispatcher_destroy()
 * 
 * @{
 */

/**
 * @brief Opaque dispatcher structure.
 */
struct dispatcher;

/**
 * @brief Create a new dispatcher.
 * 
 * @return New dispatcher instance, or NULL on failure.
 */
struct dispatcher *dispatcher_create(void);

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
 * Sets exit flag, processes all pending tasks, then calls dispatcher_destroy().
 * 
 * @param d Dispatcher instance.
 * @note Call from main thread. Pointer becomes invalid after return.
 */
void dispatcher_join(struct dispatcher *d);

/**
 * @brief Run dispatcher loop until dispatcher_break() is called.
 * 
 * Blocks and processes tasks continuously. Does not cleanup resources.
 * 
 * @param d Dispatcher instance.
 * @note Run in worker thread. Call dispatcher_destroy() afterward.
 */
void dispatcher_loop(struct dispatcher *d);

/**
 * @brief Signal dispatcher_loop() to exit (thread-safe).
 * 
 * @param d Dispatcher instance.
 */
void dispatcher_break(struct dispatcher *d);

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
