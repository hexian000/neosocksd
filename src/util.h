/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Public utilities, globals, and helpers. */

#ifndef UTIL_H
#define UTIL_H

#include "conf.h"
#include "transfer.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

/* Compile-time length of a string literal excluding the null terminator. */
#define CONSTSTRLEN(s) (sizeof(s "") - sizeof(""))

/* Sentinel value representing an invalid or unavailable timestamp. */
#define TSTAMP_NIL (-1.0)

/* Validate revents against accepted mask, log EV_ERROR, and early-return when
 * none of the accepted bits are set. */
#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents) & EV_ERROR) != 0) {                             \
			const int err = errno;                                 \
			LOGE_F("io error: (%d) %s", err, strerror(err));       \
		}                                                              \
		ASSERT(((revents) & ((accept) | EV_ERROR)) == (revents));      \
		if (((revents) & (accept)) == 0) {                             \
			return;                                                \
		}                                                              \
	} while (0)

/* Log a best-effort socket option failure at the call site. @p expr yields 0
 * or an errno; ENOPROTOOPT means unsupported here, not an error. */
#define LOG_SOCKOPT(what, expr)                                                \
	do {                                                                   \
		const int sockopt_err_ = (expr);                               \
		if (sockopt_err_ != 0 && sockopt_err_ != ENOPROTOOPT) {        \
			LOGW_F("%s: (%d) %s", (what), sockopt_err_,            \
			       strerror(sockopt_err_));                        \
		}                                                              \
	} while (0)

/**
 * @brief Upper bound, excluding the null terminator, on @p n bytes rendered by
 * log_escape(): the widest escape is four characters.
 */
#define LOG_ESCAPE_STRLEN(n) (4 * (n))

/**
 * @brief Render peer-chosen bytes as printable ASCII for a log line.
 * @details A log line ends at the first newline in every sink, so a byte the
 * peer chose that reaches one verbatim lets that peer end the entry there and
 * write entries of its own (CWE-117). Escapes every byte outside printable
 * ASCII -- `\n`, `\r` and `\t` in their short forms, anything else as `\xHH` --
 * plus the backslash that introduces an escape and the quote that would close
 * the value early. The mapping is injective, so the bytes read back
 * unambiguously, and an ordinary host name or user name passes through
 * unchanged. Unlike LOG_TXT_F()'s text extra, the result is part of the line
 * itself, so it survives the sinks that render no struct slog_extra -- as a
 * per-request context prefix must.
 * @param[out] buf Out buffer, always null-terminated.
 * @param maxlen Buffer size in bytes, at least 1.
 * @param[in] s Input bytes, not null-terminated.
 * @param len Number of input bytes.
 * @return Number of characters written, excluding the null terminator. Output
 * stops on a whole escape rather than splitting one, so a buffer of
 * LOG_ESCAPE_STRLEN(len) + 1 bytes never truncates.
 */
static inline size_t log_escape(
	char *restrict buf, const size_t maxlen, const char *restrict s,
	const size_t len)
{
	static const char hexdigit[] = "0123456789abcdef";
	ASSERT(maxlen > 0);
	size_t n = 0;
	for (size_t i = 0; i < len; i++) {
		const unsigned char c = (unsigned char)s[i];
		char esc[4] = { '\\', '\0', '\0', '\0' };
		size_t esclen = 2;
		switch (c) {
		case '\n':
			esc[1] = 'n';
			break;
		case '\r':
			esc[1] = 'r';
			break;
		case '\t':
			esc[1] = 't';
			break;
		case '\\':
			esc[1] = '\\';
			break;
		case '\'':
			esc[1] = '\'';
			break;
		default:
			if ('\x20' <= c && c <= '\x7e') {
				esc[0] = (char)c;
				esclen = 1;
				break;
			}
			esc[1] = 'x';
			esc[2] = hexdigit[c >> 4];
			esc[3] = hexdigit[c & 0x0f];
			esclen = 4;
			break;
		}
		if (n + esclen + 1 > maxlen) {
			break;
		}
		for (size_t k = 0; k < esclen; k++) {
			buf[n + k] = esc[k];
		}
		n += esclen;
	}
	buf[n] = '\0';
	return n;
}

/* Log a blocked-address message; the caller returns false regardless of the
 * runtime log level (this macro must not carry the control flow itself). */
#define LOG_BLOCKED(level, what, sa)                                           \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			char addr_str[64];                                     \
			sa_format(addr_str, sizeof(addr_str), sa);             \
			LOG_F(level, "blocked %s address: %s", what,           \
			      addr_str);                                       \
		}                                                              \
	} while (0)

/* Apply the outbound policy to TCP and UDP targets alike. */
static inline bool check_outbound_sa(
	const struct config *restrict conf, const struct sockaddr *restrict sa)
{
	/* sa_ipclassify() resolves an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
	 * by its embedded IPv4 address */
	switch (sa_ipclassify(sa)) {
	case IPCLASS_LOOPBACK:
		if (conf->block_loopback) {
			LOG_BLOCKED(DEBUG, "loopback", sa);
			return false;
		}
		break;
	case IPCLASS_MULTICAST:
		if (conf->block_multicast) {
			LOG_BLOCKED(DEBUG, "multicast", sa);
			return false;
		}
		break;
	case IPCLASS_LINKLOCAL:
	case IPCLASS_SITELOCAL:
	case IPCLASS_SHARED:
		/* RFC 6598 shared space (100.64.0.0/10, CGNAT) is
		 * carrier-internal infrastructure, grouped with the private
		 * ranges under block_local */
		if (conf->block_local) {
			LOG_BLOCKED(DEBUG, "local", sa);
			return false;
		}
		break;
	case IPCLASS_GLOBAL:
		if (conf->block_global) {
			LOG_BLOCKED(DEBUG, "non-local", sa);
			return false;
		}
		break;
	case IPCLASS_RESERVED:
		/* RFC 1112 reserved-for-future-use (240.0.0.0/4): non-routable */
		LOG_BLOCKED(DEBUG, "reserved", sa);
		return false;
	case IPCLASS_BROADCAST:
		/* RFC 919 limited broadcast (255.255.255.255) */
		LOG_BLOCKED(DEBUG, "broadcast", sa);
		return false;
	default:
		/* IPCLASS_UNSPECIFIED / IPCLASS_UNKNOWN: not a dialable target */
		LOG_BLOCKED(DEBUG, "invalid", sa);
		return false;
	}
	return true;
}

#undef LOG_BLOCKED

/* Process-level initializations. */
void init(int argc, char *const restrict argv[]);

/* Load libraries and initialize global subsystems. */
void loadlibs(void);

/* Clean up and unload global subsystems and resources. */
void unloadlibs(void);

/* Update a libev I/O watcher to the desired read/write event mask. */
void modify_io_events(
	struct ev_loop *restrict loop, ev_io *restrict watcher, int events);

/* Absolute time the time-jump sentinel is scheduled at. libev leaves an
 * ev_periodic with neither an interval nor a reschedule callback at its offset
 * forever, time jumps included, so this one can never become pending. */
#define TIMEJUMP_SENTINEL_AT 1e18

static inline void
timejump_cb(struct ev_loop *loop, ev_periodic *watcher, const int revents)
{
	(void)loop;
	(void)watcher;
	(void)revents;
	FAIL();
}

/* Let libev detect wall-clock jumps by timerfd instead of by waking the loop
 * once a minute, so an idle loop blocks indefinitely. @p sentinel must outlive
 * the loop; it never becomes pending and never keeps the loop alive. */
static inline void loop_watch_timejump(
	struct ev_loop *restrict loop, ev_periodic *restrict sentinel)
{
	/* starting any ev_periodic is what makes libev set up its timerfd */
	ev_periodic_init(
		sentinel, timejump_cb, TIMEJUMP_SENTINEL_AT, 0.0, NULL);
	ev_periodic_start(loop, sentinel);
	ev_unref(loop);
}

/* socket utilities */
void socket_bind_netdev(int fd, const char *restrict netdev);
void socket_set_transparent(int fd, bool tproxy);
#if WITH_TCP_KEEPALIVE_PARAMS
/* Override the kernel's keepalive timing on a keepalive-enabled socket. Each
 * parameter is left at the system default when it is not positive. */
void socket_set_keepalive(int fd, int idle, int intvl, int cnt);
#endif

/* Forward already-buffered client bytes to a freshly dialed upstream, whose
 * send buffer should be empty. Retry successful partial sends; fail on an
 * error or zero progress rather than queueing the remainder. Count sent bytes
 * into @p byt; these bytes bypass the relay. */
static inline bool forward_readahead(
	const int fd, const void *restrict data, size_t len,
	xfer_counter *restrict byt)
{
	const unsigned char *restrict p = data;
	while (len > 0) {
		size_t n = len;
		const int err = socket_send(fd, p, &n);
		xfer_count(byt, n);
		if (err != 0 || n == 0) {
			return false;
		}
		p += n;
		len -= n;
	}
	return true;
}

#endif /* UTIL_H */
