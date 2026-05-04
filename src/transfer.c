/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file transfer.c
 * @brief Bidirectional data transfer, optionally on a dedicated I/O thread.
 *
 * When built with WITH_THREADS:
 *   `struct transfer` (engine) runs an ev_loop on a dedicated C11 thread.
 *   `struct transfer_ctx` wraps two `struct xfer_half` objects (one per
 *   direction). Tasks are enqueued from the main thread via a dispatcher queue
 *   signalled with an ev_async watcher.
 *
 * When built without WITH_THREADS:
 *   The engine reuses the caller-supplied ev_loop; `transfer_start` registers
 *   I/O watchers directly on that loop without spawning a thread.
 *
 * transfer_ctx is self-owned: allocated by transfer_start(), freed once both
 * halves finish.  On completion, the atomic num_sessions counter is
 * decremented.
 */

#include "transfer.h"

#include "util.h"

#include "io/io.h"
#include "os/socket.h"
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/task.h"
#endif
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#if WITH_SPLICE
#include <fcntl.h>
#endif
#include <sys/socket.h>

#include <errno.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if WITH_THREADS
#include <threads.h>
#endif

#if WITH_THREADS
#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status = (expr);                                     \
		(void)status;                                                  \
		assert(status == thrd_success);                                \
	} while (0)
#endif /* WITH_THREADS */

/* ------------------------------------------------------------------ states */

enum xfer_half_state {
	XFER_INIT,
	XFER_CONNECTED,
	XFER_LINGER,
	XFER_FINISHED,
};

static const char *const xfer_state_str[] = {
	[XFER_INIT] = "INIT",
	[XFER_CONNECTED] = "TRANSFERRING",
	[XFER_LINGER] = "LINGER",
	[XFER_FINISHED] = "FINISHED",
};

/* ---------------------------------------------------------------- xfer_half */

/*
 * Single-direction transfer half.  All fields accessed exclusively on the
 * xfer thread after task_xfer_start enqueues the initial ev_io_start calls.
 */
struct xfer_half {
	enum xfer_half_state state;
	int src_fd, dst_fd;
	ev_io w_socket;
#if WITH_THREADS
	atomic_uintmax_t *byt_transferred;
#else
	uintmax_t *byt_transferred;
#endif
	bool is_uplink : 1;
#if WITH_SPLICE
	bool use_splice : 1;
	struct splice_pipe pipe;
#endif
	size_t pos;
	struct {
		BUFFER_HDR;
		unsigned char data[IO_BUFSIZE];
	} buf;
	/* back-pointer; set once at construction, then read-only */
	struct transfer_ctx *owner;
};

/* ---------------------------------------------------------------- transfer_ctx */

struct transfer_ctx {
	struct transfer *xfer;
	/* intrusive singly-linked list; xfer thread only */
	struct transfer_ctx *next;
	struct xfer_half up, down;
	unsigned n_finished;
	/* session counter to decrement when both halves finish */
#if WITH_THREADS
	atomic_size_t *num_sessions;
#else
	size_t *num_sessions;
#endif
};

/* ---------------------------------------------------------------- transfer (engine) */

struct transfer {
	struct ev_loop *loop;
#if WITH_THREADS
	thrd_t thread;
	struct dispatcher *disp;
	struct ev_loop *main_loop;
	/* main -> xfer: new task enqueued */
	ev_async w_invoke;
	bool stop;
#endif
	/* loop thread only; no locking needed */
	struct transfer_ctx *active_list;
};

/* ---------------------------------------------------------------- logging */

#define XFER_HALF_LOG_F(level, h, format, ...)                                 \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		if ((h)->is_uplink) {                                          \
			LOG_F(level, "[fd:%d]<-[fd:%d] " format, (h)->dst_fd,  \
			      (h)->src_fd, __VA_ARGS__);                       \
		} else {                                                       \
			LOG_F(level, "[fd:%d]->[fd:%d] " format, (h)->src_fd,  \
			      (h)->dst_fd, __VA_ARGS__);                       \
		}                                                              \
	} while (0)
#define XFER_HALF_LOG(level, h, message)                                       \
	XFER_HALF_LOG_F(level, h, "%s", message)

/* ---------------------------------------------------------------- xfer_half I/O helpers */

static void update_watcher(
	struct xfer_half *restrict h, struct ev_loop *restrict loop,
	const int events)
{
	ASSERT(events == EV_READ || events == EV_WRITE);
	ev_io *restrict w = &h->w_socket;
	const int cur = w->events & (EV_READ | EV_WRITE);
	if (cur == events) {
		return;
	}
	const int fd = (events & EV_WRITE) ? h->dst_fd : h->src_fd;
	ev_io_stop(loop, w);
	ev_io_set(w, fd, events);
	ev_io_start(loop, w);
}

static void update_stats(
	const struct xfer_half *restrict h, const size_t nbsend,
	const size_t buffered)
{
#if WITH_THREADS
	atomic_uintmax_t *restrict byt = h->byt_transferred;
	if (byt != NULL) {
		atomic_fetch_add_explicit(byt, nbsend, memory_order_relaxed);
	}
#else
	uintmax_t *restrict byt = h->byt_transferred;
	if (byt != NULL) {
		*byt += nbsend;
	}
#endif
	if (buffered > 0) {
		XFER_HALF_LOG_F(
			VERYVERBOSE, h,
			"%zu bytes transmitted (%zu bytes buffered)", nbsend,
			buffered);
		return;
	}
	XFER_HALF_LOG_F(VERYVERBOSE, h, "%zu bytes transmitted", nbsend);
}

/* ---------------------------------------------------------------- set_state */

/*
 * set_state must be called from the xfer thread only.
 * When both halves reach XFER_FINISHED the transfer is self-freed here.
 */
static void set_state(
	struct xfer_half *restrict h, struct ev_loop *restrict loop,
	const enum xfer_half_state new_state)
{
	UNUSED(loop);
	if (h->state == new_state) {
		return;
	}
	XFER_HALF_LOG_F(
		VERBOSE, h, "state changed: %s -> %s", xfer_state_str[h->state],
		xfer_state_str[new_state]);
	h->state = new_state;

	if (new_state != XFER_FINISHED) {
		return;
	}

	struct transfer_ctx *restrict t = h->owner;
	t->n_finished++;
	if (t->n_finished < 2) {
		return;
	}
	/* Both halves finished: close fds, decrement counter, free. */
	CLOSE_FD(t->up.src_fd);
	CLOSE_FD(t->down.src_fd);
	/* Remove from active_list. */
	struct transfer *restrict xfer = t->xfer;
	struct transfer_ctx **pp = &xfer->active_list;
	for (; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == t) {
			*pp = t->next;
			break;
		}
	}
#if WITH_THREADS
	atomic_fetch_sub_explicit(t->num_sessions, 1, memory_order_relaxed);
#else
	(*t->num_sessions)--;
#endif
	free(t);
}

/* ---------------------------------------------------------------- xfer_half I/O */

static ssize_t xfer_recv(struct xfer_half *restrict h)
{
	const size_t cap = h->buf.cap - h->buf.len;
	if (cap == 0) {
		return 0;
	}
	unsigned char *data = h->buf.data + h->buf.len;
	size_t n = cap;
	const int err = socket_recv(h->src_fd, data, &n);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		XFER_HALF_LOG_F(DEBUG, h, "recv: (%d) %s", err, strerror(err));
		return -1;
	}
	if (n == 0) {
		XFER_HALF_LOG(VERYVERBOSE, h, "recv: EOF");
		return -1;
	}
	h->buf.len += n;
	return (ssize_t)n;
}

static ssize_t xfer_send(struct xfer_half *restrict h)
{
	size_t len = h->buf.len - h->pos;
	if (len == 0) {
		return 0;
	}
	const unsigned char *data = h->buf.data + h->pos;
	const int err = socket_send(h->dst_fd, data, &len);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
		    err == ENOMEM) {
			return 0;
		}
		XFER_HALF_LOG_F(DEBUG, h, "send: (%d) %s", err, strerror(err));
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	h->pos += len;
	if (h->pos == h->buf.len) {
		h->pos = h->buf.len = 0;
	}
	return (ssize_t)len;
}

static void send_eof(struct xfer_half *restrict h)
{
	if (shutdown(h->dst_fd, SHUT_WR) != 0) {
		const int err = errno;
		XFER_HALF_LOG_F(
			WARNING, h, "shutdown: (%d) %s", err, strerror(err));
		return;
	}
	XFER_HALF_LOG(VERYVERBOSE, h, "shutdown: send operations disabled");
}

static void
transfer_cb(struct ev_loop *restrict loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);

	struct xfer_half *restrict h = watcher->data;
	enum xfer_half_state state = h->state;
	size_t nbsend = 0;
	while (state <= XFER_LINGER) {
		ssize_t nrecv = 0;
		if (state <= XFER_CONNECTED) {
			nrecv = xfer_recv(h);
			if (nrecv < 0) {
				state = XFER_LINGER;
			}
		}
		ssize_t nsend = xfer_send(h);
		if (nsend < 0) {
			state = XFER_FINISHED;
		} else {
			nbsend += (size_t)nsend;
		}
		if ((h->pos < h->buf.len) || (nrecv <= 0 && nsend <= 0)) {
			break;
		}
	}
	if (nbsend > 0) {
		update_stats(h, nbsend, h->buf.len);
	}

	const bool has_data = (h->pos < h->buf.len);
	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED:
		if (has_data) {
			update_watcher(h, loop, EV_WRITE);
		} else {
			update_watcher(h, loop, EV_READ);
		}
		break;
	case XFER_LINGER:
		if (has_data) {
			update_watcher(h, loop, EV_WRITE);
			break;
		}
		send_eof(h);
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &h->w_socket);
		break;
	default:
		FAILMSGF("unexpected state: %d", state);
	}
	set_state(h, loop, state);
}

#if WITH_SPLICE

static ssize_t splice_drain(struct xfer_half *restrict h, const int fd)
{
	struct splice_pipe *restrict pipe = &h->pipe;
	ASSERT(pipe->len <= pipe->cap);
	const size_t cap = pipe->cap - pipe->len;
	if (cap == 0) {
		return 0;
	}
	ssize_t nrecv;
	do {
		nrecv = splice(
			fd, NULL, pipe->fd[1], NULL, cap, SPLICE_F_NONBLOCK);
	} while (nrecv < 0 && errno == EINTR);
	if (nrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		XFER_HALF_LOG_F(
			DEBUG, h, "pipe: recv (%d) %s", err, strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		XFER_HALF_LOG(VERYVERBOSE, h, "pipe: recv EOF");
		return -1;
	}
	pipe->len += (size_t)nrecv;
	return nrecv;
}

static ssize_t splice_pump(struct xfer_half *restrict h, const int fd)
{
	struct splice_pipe *restrict pipe = &h->pipe;
	const size_t len = pipe->len;
	if (len == 0) {
		return 0;
	}
	ssize_t nsend;
	do {
		nsend = splice(
			pipe->fd[0], NULL, fd, NULL, len, SPLICE_F_NONBLOCK);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		XFER_HALF_LOG_F(
			DEBUG, h, "pipe: send (%d) %s", err, strerror(err));
		return -1;
	}
	pipe->len -= (size_t)nsend;
	return nsend;
}

static void
pipe_cb(struct ev_loop *restrict loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);

	struct xfer_half *restrict h = watcher->data;
	enum xfer_half_state state = h->state;
	size_t nbsend = 0;
	while (state <= XFER_LINGER) {
		ssize_t nrecv = 0;
		if (state <= XFER_CONNECTED) {
			nrecv = splice_drain(h, h->src_fd);
			if (nrecv < 0) {
				state = XFER_LINGER;
			}
		}
		ssize_t nsend = splice_pump(h, h->dst_fd);
		if (nsend < 0) {
			state = XFER_FINISHED;
		} else {
			nbsend += (size_t)nsend;
		}
		if (h->pipe.len > 0 || (nrecv <= 0 && nsend <= 0)) {
			break;
		}
	}
	if (nbsend > 0) {
		update_stats(h, nbsend, h->pipe.len);
	}

	const bool has_data = (h->pipe.len > 0);
	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED:
		if (has_data) {
			update_watcher(h, loop, EV_WRITE);
		} else {
			update_watcher(h, loop, EV_READ);
		}
		break;
	case XFER_LINGER:
		if (has_data) {
			update_watcher(h, loop, EV_WRITE);
			break;
		}
		send_eof(h);
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &h->w_socket);
		break;
	default:
		FAILMSGF("unexpected state: %d", state);
	}
	set_state(h, loop, state);
}

static bool pipe_get(struct splice_pipe *restrict pipe)
{
	if (pipe_cache.len == 0) {
		return pipe_new(pipe);
	}
	*pipe = pipe_cache.pipes[--pipe_cache.len];
	return true;
}

static void pipe_put(struct splice_pipe *restrict pipe)
{
	if (pipe->len > 0 || pipe_cache.len == pipe_cache.cap) {
		pipe_close(pipe);
		return;
	}
	pipe_cache.pipes[pipe_cache.len++] = *pipe;
}

#endif /* WITH_SPLICE */

/* ---------------------------------------------------------------- task_xfer_start / task_xfer_stop */

static void task_xfer_start(void *data)
{
	struct transfer_ctx *restrict t = data;
	struct transfer *restrict xfer = t->xfer;
	struct ev_loop *restrict loop = xfer->loop;
	/* Prepend to active list before starting I/O watchers. */
	t->next = xfer->active_list;
	xfer->active_list = t;

#if WITH_SPLICE
	if (t->up.use_splice) {
		struct splice_pipe pipe;
		if (pipe_get(&pipe)) {
			ev_set_cb(&t->up.w_socket, pipe_cb);
			t->up.pipe = pipe;
		}
	}
	if (t->down.use_splice) {
		struct splice_pipe pipe;
		if (pipe_get(&pipe)) {
			ev_set_cb(&t->down.w_socket, pipe_cb);
			t->down.pipe = pipe;
		}
	}
#endif

	ev_io_start(loop, &t->up.w_socket);
	ev_io_start(loop, &t->down.w_socket);
}

/*
 * task_xfer_stop: cancel a single in-flight transfer from the xfer thread.
 * Called during engine shutdown for every entry in active_list.
 */
static void
task_xfer_stop(struct ev_loop *restrict loop, struct transfer_ctx *restrict t)
{
	ev_io_stop(loop, &t->up.w_socket);
	ev_io_stop(loop, &t->down.w_socket);

#if WITH_SPLICE
	if (t->up.pipe.fd[0] != -1) {
		pipe_put(&t->up.pipe);
	}
	if (t->down.pipe.fd[0] != -1) {
		pipe_put(&t->down.pipe);
	}
#endif

	CLOSE_FD(t->up.src_fd);
	CLOSE_FD(t->down.src_fd);
#if WITH_THREADS
	atomic_fetch_sub_explicit(t->num_sessions, 1, memory_order_relaxed);
#else
	(*t->num_sessions)--;
#endif
	free(t);
}

/* ---------------------------------------------------------------- engine callbacks */

#if WITH_THREADS

static void
w_invoke_cb(struct ev_loop *restrict loop, ev_async *watcher, const int revents)
{
	UNUSED(revents);
	struct transfer *restrict xfer = watcher->data;
	dispatcher_tick(xfer->disp);
	if (xfer->stop) {
		ev_break(loop, EVBREAK_ONE);
	}
}

/* ---------------------------------------------------------------- xfer thread */

static int xfer_thread_func(void *arg)
{
	struct transfer *restrict xfer = arg;
	struct ev_loop *restrict loop = xfer->loop;
	ev_run(loop, 0);
	/* Cancel any transfers that are still in flight at shutdown. */
	for (struct transfer_ctx *t = xfer->active_list; t != NULL;) {
		struct transfer_ctx *next = t->next;
		task_xfer_stop(loop, t);
		t = next;
	}
	xfer->active_list = NULL;
	return 0;
}

#endif /* WITH_THREADS */

/* ---------------------------------------------------------------- public API */

struct transfer *transfer_new(struct ev_loop *restrict loop)
{
	struct transfer *restrict xfer = malloc(sizeof(struct transfer));
	if (xfer == NULL) {
		return NULL;
	}
	xfer->active_list = NULL;

#if WITH_THREADS
	xfer->main_loop = loop;
	xfer->stop = false;
	xfer->disp = NULL;
	xfer->loop = NULL;

	xfer->disp = dispatcher_create(16);
	if (xfer->disp == NULL) {
		transfer_free(xfer);
		return NULL;
	}

	xfer->loop = ev_loop_new(0);
	if (xfer->loop == NULL) {
		transfer_free(xfer);
		return NULL;
	}

	ev_async_init(&xfer->w_invoke, w_invoke_cb);
	ev_set_priority(&xfer->w_invoke, EV_MAXPRI);
	xfer->w_invoke.data = xfer;
	ev_async_start(xfer->loop, &xfer->w_invoke);

	if (thrd_create(&xfer->thread, xfer_thread_func, xfer) !=
	    thrd_success) {
		ev_async_stop(xfer->loop, &xfer->w_invoke);
		ev_loop_destroy(xfer->loop);
		xfer->loop = NULL;
		transfer_free(xfer);
		return NULL;
	}
#else
	xfer->loop = loop;
#endif
	return xfer;
}

void transfer_free(struct transfer *restrict xfer)
{
	if (xfer == NULL) {
		return;
	}
#if WITH_THREADS
	if (xfer->loop != NULL) {
		xfer->stop = true;
		ev_async_send(xfer->loop, &xfer->w_invoke);
		THRD_ASSERT(thrd_join(xfer->thread, NULL));
		/* xfer_thread_func has cancelled all in-flight transfers. */
		ev_async_stop(xfer->loop, &xfer->w_invoke);
		ev_loop_destroy(xfer->loop);
		xfer->loop = NULL;
	}
	if (xfer->disp != NULL) {
		dispatcher_destroy(xfer->disp);
		xfer->disp = NULL;
	}
#else
	/* Cancel any in-flight transfers. */
	for (struct transfer_ctx *t = xfer->active_list; t != NULL;) {
		struct transfer_ctx *next = t->next;
		task_xfer_stop(xfer->loop, t);
		t = next;
	}
	xfer->active_list = NULL;
#endif
	free(xfer);
}

static void xfer_half_init(
	struct xfer_half *restrict h, struct transfer_ctx *restrict owner,
	const int src_fd, const int dst_fd,
#if WITH_THREADS
	atomic_uintmax_t *restrict byt_transferred,
#else
	uintmax_t *restrict byt_transferred,
#endif
	const bool is_uplink
#if WITH_SPLICE
	,
	const bool use_splice
#endif
)
{
	h->state = XFER_INIT;
	h->src_fd = src_fd;
	h->dst_fd = dst_fd;
	ev_io_init(&h->w_socket, transfer_cb, src_fd, EV_READ);
	h->w_socket.data = h;
	h->byt_transferred = byt_transferred;
	h->is_uplink = is_uplink;
	h->owner = owner;
#if WITH_SPLICE
	h->use_splice = use_splice;
	h->pipe = (struct splice_pipe){ .fd = { -1, -1 }, .cap = 0, .len = 0 };
#endif
	h->pos = 0;
	BUF_INIT(h->buf, 0);
}

bool transfer_serve(
	struct transfer *restrict xfer, const int acc_fd, const int dial_fd,
	const struct transfer_opts *restrict opts)
{
	struct transfer_ctx *restrict t = malloc(sizeof(struct transfer_ctx));
	if (t == NULL) {
		return false;
	}
	t->xfer = xfer;
	t->next = NULL;
	t->n_finished = 0;
	t->num_sessions = opts->num_sessions;

	xfer_half_init(
		&t->up, t, acc_fd, dial_fd, opts->byt_up, true
#if WITH_SPLICE
		,
		opts->use_splice
#endif
	);
	xfer_half_init(
		&t->down, t, dial_fd, acc_fd, opts->byt_down, false
#if WITH_SPLICE
		,
		opts->use_splice
#endif
	);

#if WITH_THREADS
	if (!dispatcher_invoke(
		    xfer->disp,
		    (struct task){ .func = task_xfer_start, .data = t })) {
		free(t);
		return false;
	}
	ev_async_send(xfer->loop, &xfer->w_invoke);
#else
	task_xfer_start(t);
#endif
	return true;
}
