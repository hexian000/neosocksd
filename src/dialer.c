/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "dialer.h"

#include "conf.h"
#include "proto/domain.h"
#include "proto/http.h"
#include "proto/socks.h"
#include "resolver.h"
#include "server.h"
#include "util.h"

#include "binary/serialize.h"
#include "codec/base64.h"
#include "meta/arraysize.h"
#include "net/http.h"
#include "net/url.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/ctype_ascii.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

const char *const proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

/* True when a name can be written into every message this dialer sends. An
 * HTTP hop renders the destination into the CONNECT request-line and the Host
 * field, which RFC 9112 3 frames on the space and the CRLF, so a name carrying
 * one of those writes header fields and a whole second request of the peer's
 * choosing. A host name spells none of them to begin with: RFC 1035 2.3.1 with
 * RFC 1123 2.1 build one from ASCII letters, digits and hyphens, and RFC 5891 5
 * dials a non-ASCII name as its ASCII A-label. Admit the printable ASCII an
 * RFC 3986 host may spell, and nothing else -- and at least one byte of it.
 * Those same grammars build a name out of labels and a label out of at least
 * one character, so the empty string names nothing: written into a CONNECT it
 * leaves the request-target and the Host field without the host RFC 9110 9.3.6
 * requires them to carry, and handed to another hop it is a name that hop
 * cannot dial either. */
static bool is_host_name(const char *restrict name, const size_t len)
{
	if (len == 0) {
		return false;
	}
	for (size_t i = 0; i < len; i++) {
		const unsigned char c = (unsigned char)name[i];
		/* the space and the delete bound printable ASCII */
		if (c <= '\x20' || '\x7e' < c) {
			return false;
		}
	}
	return true;
}

/* Set an address from a URI authority's host and port. RFC 3986 3.2.2 spells
 * the bracketed form as IP-literal = "[" ( IPv6address / IPvFuture ) "]" and
 * admits no bracket in a reg-name, so a bracketed host must be an IPv6 address:
 * an IPvFuture literal names nothing this dialer can reach, and an IPv4 address
 * or a domain name is written unbracketed. */
static bool dialaddr_sethostport(
	struct dialaddr *restrict addr, const char *restrict host,
	const bool bracketed, const uint_fast16_t port)
{
	if (port == 0) {
		/* RFC 6335 6 reserves port 0: no TCP peer answers there */
		LOG_TXT(ERROR, host, strlen(host), "port 0 is not dialable:");
		return false;
	}
	addr->port = port;
	if (inet_pton(AF_INET6, host, &addr->in6) == 1) {
		addr->type = ATYP_INET6;
		return true;
	}
	if (bracketed) {
		LOG_TXT(ERROR, host, strlen(host), "not an IPv6 literal:");
		return false;
	}
	if (inet_pton(AF_INET, host, &addr->in) == 1) {
		addr->type = ATYP_INET;
		return true;
	}
	const size_t hostlen = strlen(host);
	if (hostlen > FQDN_MAX_LENGTH) {
		LOG_TXT_F(
			ERROR, host, hostlen, 0, "hostname too long: %zu bytes",
			hostlen);
		return false;
	}
	if (!is_host_name(host, hostlen)) {
		LOG_TXT(ERROR, host, hostlen, "not a host name:");
		return false;
	}
	struct domain_name *restrict domain = &addr->domain;
	memcpy(domain->name, host, hostlen);
	domain->len = (uint_least8_t)hostlen;
	addr->type = ATYP_DOMAIN;
	return true;
}

/* Parse a decimal port number in [0, UINT16_MAX]; an empty string parses as 0.
 * Logs and returns false on trailing garbage or overflow. */
static bool parse_port(const char *restrict port, uint_fast16_t *restrict out)
{
	/* RFC 3986 spells a port as *DIGIT, but strtoumax() skips leading
	 * whitespace and accepts a sign; require a digit, or nothing at all. */
	if (port[0] != '\0' && !isdigit((unsigned char)port[0])) {
		LOG_TXT(ERROR, port, strlen(port),
			"unable to parse port number:");
		return false;
	}
	char *endptr;
	const uintmax_t portvalue = strtoumax(port, &endptr, 10);
	if (*endptr || portvalue > UINT16_MAX) {
		LOG_TXT(ERROR, port, strlen(port),
			"unable to parse port number:");
		return false;
	}
	*out = (uint_fast16_t)portvalue;
	return true;
}

/* Split a URI authority into a host and an optional port, left NULL when the
 * authority carries none, reporting through @p bracketed whether the host was
 * an IP literal. The brackets are stripped; an empty host, an unbracketed
 * multi-colon literal and a malformed bracket are rejected. An empty port
 * subcomponent is none: RFC 3986 3.2.3 spells a port as *DIGIT and has a
 * normalizer drop an empty one, which RFC 9110 4.2.1 then reads as the
 * scheme's default. */
static bool split_authority(
	char *restrict authority, char **restrict host, char **restrict port,
	bool *restrict bracketed)
{
	if (authority[0] == '[') {
		/* RFC 3986 3.2.2: an IP literal is bracketed */
		char *const rbracket = strchr(authority, ']');
		if (rbracket == NULL || rbracket == authority + 1) {
			return false;
		}
		if (rbracket[1] != '\0' && rbracket[1] != ':') {
			return false;
		}
		*host = authority + 1;
		*port = (rbracket[1] == ':' && rbracket[2] != '\0') ?
				rbracket + 2 :
				NULL;
		*bracketed = true;
		*rbracket = '\0';
		return true;
	}
	*bracketed = false;
	char *const colon = strchr(authority, ':');
	if (colon == NULL) {
		if (authority[0] == '\0') {
			return false;
		}
		*host = authority;
		*port = NULL;
		return true;
	}
	if (colon == authority || strchr(colon + 1, ':') != NULL) {
		/* an empty host, or an unbracketed IPv6 literal that is
		 * ambiguous with "host:port" */
		return false;
	}
	*colon = '\0';
	*host = authority;
	*port = (colon[1] != '\0') ? colon + 1 : NULL;
	return true;
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	if (len > DIALADDR_STRLEN) {
		LOG_TXT_F(ERROR, s, len, 0, "address too long: %zu bytes", len);
		return false;
	}
	if (memchr(s, '\0', len) != NULL) {
		LOG_TXT(ERROR, s, len, "invalid address:");
		return false;
	}
	char buf[len + 1];
	memcpy(buf, s, len);
	buf[len] = '\0';

	char *host, *port;
	bool bracketed;
	/* unlike a proxy URI's authority, an address always carries a port */
	if (!split_authority(buf, &host, &port, &bracketed) || port == NULL) {
		LOG_TXT(ERROR, s, len, "invalid address:");
		return false;
	}
	uint_fast16_t port_num;
	if (!parse_port(port, &port_num)) {
		return false;
	}
	return dialaddr_sethostport(addr, host, bracketed, port_num);
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	switch (sa->sa_family) {
	case AF_INET:
		if ((size_t)len < sizeof(struct sockaddr_in)) {
			return false;
		}
		addr->type = ATYP_INET;
		addr->in = ((const struct sockaddr_in *)sa)->sin_addr;
		addr->port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
		return true;
	case AF_INET6:
		if ((size_t)len < sizeof(struct sockaddr_in6)) {
			return false;
		}
		addr->type = ATYP_INET6;
		addr->in6 = ((const struct sockaddr_in6 *)sa)->sin6_addr;
		addr->port =
			ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
		return true;
	default:;
	}
	return false;
}

void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src)
{
	dst->type = src->type;
	dst->port = src->port;
	switch (src->type) {
	case ATYP_INET:
		dst->in = src->in;
		break;
	case ATYP_INET6:
		dst->in6 = src->in6;
		break;
	case ATYP_DOMAIN: {
		const uint_fast8_t len = (uint_fast8_t)src->domain.len;
		dst->domain.len = len;
		memcpy(dst->domain.name, src->domain.name, len);
	} break;
	default:
		FAILMSGF("unexpected address type: %d", src->type);
	}
}

int dialaddr_format(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	switch (addr->type) {
	case ATYP_INET: {
		char buf[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &addr->in, buf, sizeof(buf)) == NULL) {
			return -1;
		}
		return snprintf(s, maxlen, "%s:%" PRIuLEAST16, buf, addr->port);
	}
	case ATYP_INET6: {
		char buf[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, &addr->in6, buf, sizeof(buf)) == NULL) {
			return -1;
		}
		return snprintf(
			s, maxlen, "[%s]:%" PRIuLEAST16, buf, addr->port);
	}
	case ATYP_DOMAIN:
		return snprintf(
			s, maxlen, "%.*s:%" PRIuLEAST16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	default:
		break;
	}
	FAILMSGF("unexpected address type: %d", addr->type);
}

static const char *const dialer_error_strs[DIALER_ERR_MAX] = {
	[DIALER_OK] = "success",
	[DIALER_CANCELLED] = "operation cancelled",
	[DIALER_ERR_SYSTEM] = "system error",
	[DIALER_ERR_RESOLVE] = "name resolution failed",
	[DIALER_ERR_CONNECT] = "connection failed",
	[DIALER_ERR_PROXY_PROTO] = "proxy protocol error",
	[DIALER_ERR_PROXY_AUTH] = "proxy authentication failed",
	[DIALER_ERR_PROXY_REFUSED] = "proxy refused connection",
	[DIALER_ERR_PROXY_REJECT] = "request rejected by proxy",
	[DIALER_ERR_EOF] = "unexpected end of connection",
	[DIALER_ERR_BLOCKED] = "connection blocked by policy",
	[DIALER_ERR_BADADDR] = "invalid address",
};

const char *dialer_strerror(const enum dialer_error err)
{
	/* The underlying type of an enum is implementation-defined and may be
	 * signed, so compare as unsigned to bound both ends: a negative
	 * (corrupted/foreign) value would otherwise index before the array. */
	if ((unsigned int)err < DIALER_ERR_MAX &&
	    dialer_error_strs[err] != NULL) {
		return dialer_error_strs[err];
	}
	return "unknown error";
}

#define DIALREQ_NEW(n)                                                         \
	(malloc(sizeof(struct dialreq) + sizeof(struct proxyreq) * (n)))

static bool proxy_set_credential(
	struct proxyreq *restrict proxy, const char *restrict username,
	const char *restrict password)
{
	const size_t ulen = (username != NULL) ? strlen(username) + 1 : 0;
	const size_t plen = (password != NULL) ? strlen(password) + 1 : 0;
	if (ulen + plen > sizeof(proxy->credential)) {
		return false;
	}
	if (username != NULL) {
		proxy->username = proxy->credential;
		memcpy(proxy->username, username, ulen);
	} else {
		proxy->username = NULL;
	}
	if (password != NULL) {
		proxy->password = proxy->credential + ulen;
		memcpy(proxy->password, password, plen);
	} else {
		proxy->password = NULL;
	}
	return true;
}

static bool
proxy_copy(struct proxyreq *restrict dst, const struct proxyreq *restrict src)
{
	dst->proto = src->proto;
	dialaddr_copy(&dst->addr, &src->addr);
	return proxy_set_credential(dst, src->username, src->password);
}

struct dialreq *
dialreq_new(const struct dialreq *restrict base, const size_t num_proxy)
{
	const size_t num_base_proxy = (base != NULL) ? base->num_proxy : 0;
	struct dialreq *restrict req = DIALREQ_NEW(num_base_proxy + num_proxy);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	req->num_proxy = num_base_proxy;
	req->num_proxy_max = num_base_proxy + num_proxy;
	if (base != NULL) {
		dialaddr_copy(&req->addr, &base->addr);
		for (size_t i = 0; i < num_base_proxy; i++) {
			if (!proxy_copy(&req->proxy[i], &base->proxy[i])) {
				LOGE_F("proxy credential too long: [%zu]", i);
				dialreq_free(req);
				return NULL;
			}
		}
	} else {
		/* No base to copy the target address from; install an explicit
		 * INADDR_ANY wildcard rather than leaving req->addr
		 * indeterminate, matching dialreq_parse's no-address path. */
		req->addr = (struct dialaddr){
			.type = ATYP_INET,
			.port = UINT16_C(0),
			.in = { INADDR_ANY },
		};
	}
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	/* should be more than enough */
	if (urilen >= 1024) {
		LOG_TXT_F(
			ERROR, proxy_uri, urilen, 0,
			"proxy uri is too long: %zu bytes", urilen);
		return false;
	}
	if (req->num_proxy >= req->num_proxy_max) {
		LOGE_F("proxy chain is full: %zu", req->num_proxy_max);
		return false;
	}
	if (memchr(proxy_uri, '\0', urilen) != NULL) {
		LOG_TXT(ERROR, proxy_uri, urilen, "unable to parse uri:");
		return false;
	}
	char buf[urilen + 1];
	memcpy(buf, proxy_uri, urilen);
	buf[urilen] = '\0';
	struct url uri;
	if (!url_parse(buf, &uri) || uri.scheme == NULL || uri.host == NULL) {
		LOG_TXT(ERROR, proxy_uri, urilen, "unable to parse uri:");
		return false;
	}
	enum proxy_protocol protocol;
	const char *defport;
	if (strcmp(uri.scheme, proxy_protocol_str[PROTO_HTTP]) == 0) {
		protocol = PROTO_HTTP;
		defport = "80";
	} else if (strcmp(uri.scheme, proxy_protocol_str[PROTO_SOCKS4A]) == 0) {
		protocol = PROTO_SOCKS4A;
		defport = "1080";
	} else if (strcmp(uri.scheme, proxy_protocol_str[PROTO_SOCKS5]) == 0) {
		protocol = PROTO_SOCKS5;
		defport = "1080";
	} else {
		LOG_TXT(ERROR, uri.scheme, strlen(uri.scheme),
			"unknown proxy scheme:");
		return false;
	}
	char *host, *port;
	bool bracketed;
	if (!split_authority(uri.host, &host, &port, &bracketed)) {
		LOG_TXT(ERROR, proxy_uri, urilen, "invalid proxy authority:");
		return false;
	}
	uint_fast16_t port_num;
	if (!parse_port((port != NULL) ? port : defport, &port_num)) {
		return false;
	}
	struct proxyreq *restrict proxy = &req->proxy[req->num_proxy];
	proxy->proto = protocol;
	if (!dialaddr_sethostport(&proxy->addr, host, bracketed, port_num)) {
		return false;
	}
	proxy->username = NULL;
	proxy->password = NULL;
	if (uri.userinfo != NULL) {
		char *username, *password;
		if (!url_unescape_userinfo(uri.userinfo, &username, &password) ||
		    !proxy_set_credential(proxy, username, password)) {
			LOG_TXT(ERROR, uri.userinfo, strlen(uri.userinfo),
				"invalid proxy userinfo:");
			return false;
		}
	}
	req->num_proxy++;
	return true;
}

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	size_t n = 0;
	if (csv != NULL) {
		const size_t len = strlen(csv);
		/* bound the allocation below before sizing it */
		if (len > UINT16_MAX) {
			LOGE_F("proxy chain too long: %zu bytes", len);
			return NULL;
		}
		if (len > 0) {
			n = 1;
		}
		for (size_t i = 0; i < len; i++) {
			if (csv[i] == ',') {
				++n;
			}
		}
	}
	struct dialreq *restrict req = DIALREQ_NEW(n);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	req->num_proxy = 0;
	req->num_proxy_max = n;
	/* A missing address and CONF_FORWARD_ANY both leave the destination to a
	 * ruleset. Only the configuration reaches here; dialaddr_parse() still
	 * refuses a host-less authority wherever a peer's address arrives. */
	if (addr == NULL || strcmp(addr, CONF_FORWARD_ANY) == 0) {
		req->addr = (struct dialaddr){
			.type = ATYP_INET,
			.port = UINT16_C(0),
			.in = { INADDR_ANY },
		};
	} else if (!dialaddr_parse(&req->addr, addr, strlen(addr))) {
		dialreq_free(req);
		return NULL;
	}
	if (n > 0) {
		/* empty elements (adjacent or trailing commas) are skipped */
		for (const char *tok = csv;;) {
			const char *const comma = strchr(tok, ',');
			const size_t toklen = (comma != NULL) ?
						      (size_t)(comma - tok) :
						      strlen(tok);
			if (toklen > 0 && !dialreq_addproxy(req, tok, toklen)) {
				dialreq_free(req);
				return NULL;
			}
			if (comma == NULL) {
				break;
			}
			tok = comma + 1;
		}
	}
	return req;
}

static int format_proxyreq(
	char *restrict s, const size_t maxlen,
	const struct proxyreq *restrict req)
{
	char host[DIALADDR_STRLEN + 1];
	const int nhost = dialaddr_format(host, sizeof(host), &req->addr);
	if (nhost < 0) {
		return nhost;
	}
	const struct url u = {
		/* url_build reads the struct as const; scheme is char * only
		 * because struct url predates const-correctness */
		.scheme = (char *)proxy_protocol_str[req->proto],
		.host = host,
	};
	return url_build(s, maxlen, &u);
}

/* Remaining writable capacity at offset n, snprintf-style: zero when the buffer
 * is absent or already full. */
static size_t
format_avail(const char *restrict s, const int n, const size_t maxlen)
{
	if (s == NULL || (size_t)n >= maxlen) {
		return 0;
	}
	return maxlen - (size_t)n;
}

int dialreq_format(
	char *restrict s, size_t maxlen, const struct dialreq *restrict r)
{
	int n = 0;
	for (size_t i = 0; i < r->num_proxy; i++) {
		{
			const size_t avail = format_avail(s, n, maxlen);
			const int ret = format_proxyreq(
				avail > 0 ? s + n : NULL, avail, &r->proxy[i]);
			if (ret < 0) {
				return ret;
			}
			n += ret;
		}
		{
			const size_t avail = format_avail(s, n, maxlen);
			const int ret =
				snprintf(avail > 0 ? s + n : NULL, avail, "->");
			ASSERT(ret > 0);
			n += ret;
		}
	}
	const size_t avail = format_avail(s, n, maxlen);
	const int ret =
		dialaddr_format(avail > 0 ? s + n : NULL, avail, &r->addr);
	if (ret < 0) {
		return ret;
	}
	n += ret;
	return n;
}

void dialreq_free(struct dialreq *restrict req)
{
	free(req);
}

bool dialreq_replace(
	struct dialreq **restrict req, const char *restrict addr,
	const char *restrict csv)
{
	struct dialreq *restrict newreq = dialreq_parse(addr, csv);
	if (newreq == NULL) {
		return false;
	}
	dialreq_free(*req);
	*req = newreq;
	return true;
}

/* Tear down every connection attempt still in flight, closing its socket --
 * except @p keep_fd, the one the dial goes on with. */
static void
attempt_stop(struct dialer *restrict d, struct ev_loop *loop, const int keep_fd)
{
	ev_timer_stop(loop, &d->w_delay);
	for (size_t i = 0; i < ARRAY_SIZE(d->w_attempt); i++) {
		ev_io *restrict w = &d->w_attempt[i];
		const int fd = w->fd;
		if (fd < 0) {
			continue;
		}
		ev_io_stop(loop, w);
		ev_io_set(w, -1, EV_NONE);
		if (fd != keep_fd) {
			socket_close(fd);
		}
	}
	d->num_inflight = 0;
}

static void dialer_stop(struct dialer *restrict d, struct ev_loop *loop)
{
	switch (d->state) {
	case DIALER_STATE_INIT:
		break;
	case DIALER_STATE_RESOLVE:
		if (d->resolve_query != NULL) {
			resolve_cancel(d->resolve_query);
			d->resolve_query = NULL;
		}
		break;
	case DIALER_STATE_CONNECT:
		/* the sockets being connected are the attempts' own; the
		 * winner, if there is one by now, is already the dialed one */
		attempt_stop(d, loop, d->dialed_fd);
		break;
	case DIALER_STATE_HANDSHAKE1:
	case DIALER_STATE_HANDSHAKE2:
	case DIALER_STATE_HANDSHAKE3:
		ev_io_stop(loop, &d->w_socket);
		break;
	case DIALER_STATE_DONE:
		break;
	default:;
	}
	ASSERT(!ev_is_active(&d->w_socket) && !ev_is_pending(&d->w_socket));

	/* Close socket if connection wasn't successful */
	if (d->dialed_fd == -1 && d->w_socket.fd != -1) {
		socket_close(d->w_socket.fd);
	}
	d->state = DIALER_STATE_DONE;
}

static void
finish_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct dialer *restrict d = watcher->data;
	const int fd = d->dialed_fd;
	LOGV_F("dialer [%p]: request finished [fd:%d]", (void *)d->req, fd);
	dialer_stop(d, loop);
	if (fd >= 0 && d->server != NULL) {
		struct server_stats *restrict stats = &d->server->stats;
		const int_fast64_t elapsed =
			clock_monotonic_ns() - (int_fast64_t)d->start_ns;
		stats->connect_ns
			[stats->num_connects % ARRAY_SIZE(stats->connect_ns)] =
			(int_least64_t)elapsed;
		stats->num_connects++;
	}
	d->finish_cb.func(loop, d->finish_cb.data, fd);
}

static int format_status(
	char *restrict s, const size_t maxlen, const struct dialer *restrict d)
{
	const size_t jump = d->jump;
	const struct dialreq *restrict req = d->req;
	ASSERT(jump < req->num_proxy);
	char raddr[DIALADDR_STRLEN + 1], proxy[PROXYREQ_STRLEN + 1];
	const struct dialaddr *restrict addr = &req->addr;
	if (jump + 1 < req->num_proxy) {
		addr = &req->proxy[jump + 1].addr;
	}
	const int nraddr = dialaddr_format(raddr, sizeof(raddr), addr);
	if (nraddr < 0 || (size_t)nraddr >= sizeof(raddr)) {
		return -1;
	}
	const int nproxy =
		format_proxyreq(proxy, sizeof(proxy), &req->proxy[jump]);
	if (nproxy < 0 || (size_t)nproxy >= sizeof(proxy)) {
		return -1;
	}
	/* the destination is the name the peer wrote, so escape it inline:
	 * this is a context prefix and LOG_TXT_F()'s text extra reaches only
	 * the terminal and stream sinks. The proxy URI is escaped alongside it
	 * so the whole prefix is one line of printable ASCII. */
	char eraddr[LOG_ESCAPE_STRLEN(DIALADDR_STRLEN) + 1];
	(void)log_escape(eraddr, sizeof(eraddr), raddr, (size_t)nraddr);
	char eproxy[LOG_ESCAPE_STRLEN(PROXYREQ_STRLEN) + 1];
	(void)log_escape(eproxy, sizeof(eproxy), proxy, (size_t)nproxy);
	return snprintf(
		s, maxlen, "connect `%s' over [%zu] `%s'", eraddr, jump,
		eproxy);
}

/* Upper bound (excluding NUL) on the line format_status() builds: the fixed
 * text, a proxy index (%zu), the escaped destination dialaddr, and the escaped
 * proxy URI. */
#define DIALER_STATUS_STRLEN                                                   \
	(CONSTSTRLEN("connect `' over [] `'") +                                \
	 CONSTSTRLEN("18446744073709551615") /* max size_t decimal digits */ + \
	 LOG_ESCAPE_STRLEN(DIALADDR_STRLEN) +                                  \
	 LOG_ESCAPE_STRLEN(PROXYREQ_STRLEN))

#define DIALER_LOG_F(level, d, format, ...)                                      \
	do {                                                                     \
		if (!LOGLEVEL(level)) {                                          \
			break;                                                   \
		}                                                                \
		char status_str[DIALER_STATUS_STRLEN + 1];                       \
		const int nstatus =                                              \
			format_status(status_str, sizeof(status_str), (d));      \
		if (nstatus < 0) {                                               \
			/* format_status left status_str unwritten; skip       \
			 * rather than feed a negative %.*s precision */ \
			break;                                                   \
		}                                                                \
		LOG_F(level, "%.*s: " format, nstatus, status_str,               \
		      __VA_ARGS__);                                              \
	} while (0)
#define DIALER_LOG(level, d, message) DIALER_LOG_F(level, d, "%s", message)

static bool dialer_send(
	struct dialer *restrict d, const unsigned char *restrict buf,
	const size_t len)
{
	const int fd = d->w_socket.fd;
	LOG_BIN_F(VERYVERBOSE, buf, len, 0, "send: [fd:%d] %zu bytes", fd, len);
	ssize_t nsend;
	do {
		nsend = send(fd, buf, len, 0);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		const int err = errno;
		DIALER_LOG_F(
			DEBUG, d, "send: [fd:%d] (%d) %s", fd, err,
			strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return false;
	}
	if ((size_t)nsend != len) {
		DIALER_LOG_F(
			DEBUG, d, "send: [fd:%d] short send %zu < %zu", fd,
			(size_t)nsend, len);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return false;
	}
	if (d->byt_sent != NULL) {
		*d->byt_sent += (uint_least64_t)nsend;
	}
	return true;
}

/* Base64-encoded length of an n-byte input, matching base64_encode()'s
 * 4 * ((n + 2) / 3) padded output. Defined here because codec/base64.h is
 * vendored (read-only). */
#define BASE64_ENCODE_LEN(n) (4 * (((n) + 2) / 3))

#define DIALER_HTTP_REQ_MAXLEN                                                 \
	(CONSTSTRLEN("CONNECT ") + DIALADDR_STRLEN +                           \
	 CONSTSTRLEN(" HTTP/1.1\r\n") + CONSTSTRLEN("Host: ") +                \
	 DIALADDR_STRLEN + CONSTSTRLEN("\r\n") +                               \
	 CONSTSTRLEN("Proxy-Authorization: Basic ") +                          \
	 BASE64_ENCODE_LEN(sizeof(((struct proxyreq *)0)->credential)) +       \
	 CONSTSTRLEN("\r\n") + CONSTSTRLEN("\r\n"))

#define HTTP_RSP_MINLEN (CONSTSTRLEN("HTTP/2 200 \r\n\r\n"))

/* RFC 7231: 4.3.6.  CONNECT */
static bool send_http_req(
	struct dialer *restrict d, const struct proxyreq *restrict proxy,
	const struct dialaddr *restrict addr)
{
	char buf[DIALER_HTTP_REQ_MAXLEN];
	/* the request-target authority; RFC 9112 3.2 requires an HTTP/1.1
	 * request to carry a Host field identical to it, and strict proxies
	 * reject a Host-less CONNECT with 400. A domain name here is printable
	 * ASCII (struct dialaddr), so neither can be framed by its content. */
	char authority[DIALADDR_STRLEN + 1];
	const int alen = dialaddr_format(authority, sizeof(authority), addr);
	if (alen < 0 || (size_t)alen >= sizeof(authority)) {
		DIALER_LOG(DEBUG, d, "failed to format host address");
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return false;
	}
#define APPEND(b, s)                                                           \
	do {                                                                   \
		if ((b) + CONSTSTRLEN(s) > buf + sizeof(buf)) {                \
			DIALER_LOG(DEBUG, d, "buffer overflow");               \
			d->err = DIALER_ERR_PROXY_PROTO;                       \
			d->syserr = 0;                                         \
			return false;                                          \
		}                                                              \
		memcpy((b), (s), CONSTSTRLEN(s));                              \
		(b) += CONSTSTRLEN(s);                                         \
	} while (0)
#define APPEND_N(b, s, len)                                                    \
	do {                                                                   \
		if ((b) + (len) > buf + sizeof(buf)) {                         \
			DIALER_LOG(DEBUG, d, "buffer overflow");               \
			d->err = DIALER_ERR_PROXY_PROTO;                       \
			d->syserr = 0;                                         \
			return false;                                          \
		}                                                              \
		memcpy((b), (s), (len));                                       \
		(b) += (len);                                                  \
	} while (0)
	char *b = buf;
	APPEND(b, "CONNECT ");
	APPEND_N(b, authority, (size_t)alen);
	APPEND(b, " HTTP/1.1\r\n");
	APPEND(b, "Host: ");
	APPEND_N(b, authority, (size_t)alen);
	APPEND(b, "\r\n");
	if (proxy->username != NULL) {
		APPEND(b, "Proxy-Authorization: Basic ");
		const size_t ulen = strlen(proxy->username);
		const size_t plen =
			(proxy->password != NULL) ? strlen(proxy->password) : 0;
		const size_t srclen = ulen + 1 + plen;
		unsigned char src[srclen];
		memcpy(src, proxy->username, ulen);
		src[ulen] = ':';
		if (plen > 0) {
			memcpy(src + ulen + 1, proxy->password, plen);
		}
		size_t len = sizeof(buf) - (b - buf);
		const bool ok =
			base64_encode((unsigned char *)b, &len, src, srclen);
		if (!ok || b + len > buf + sizeof(buf)) {
			DIALER_LOG(DEBUG, d, "failed to format credential");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return false;
		}
		b += len;
		APPEND(b, "\r\n");
	}
	APPEND(b, "\r\n");
#undef APPEND
#undef APPEND_N

	if (!dialer_send(d, (unsigned char *)buf, (size_t)(b - buf))) {
		return false;
	}
	/* SO_RCVLOWAT is a wakeup hint; failure only affects efficiency */
	LOG_SOCKOPT(
		"socket_rcvlowat",
		socket_rcvlowat(d->w_socket.fd, HTTP_RSP_MINLEN));
	return true;
}

static bool send_socks4a_req(
	struct dialer *restrict d, const struct proxyreq *restrict proxy,
	const struct dialaddr *restrict addr)
{
	size_t cap = SOCKS4_HDR_LEN;
	const size_t idlen =
		(proxy->username != NULL) ? strlen(proxy->username) : 0;
	cap += idlen + 1;
	switch (addr->type) {
	case ATYP_INET:
		break;
	case ATYP_INET6:
		cap += INET6_ADDRSTRLEN;
		break;
	case ATYP_DOMAIN:
		cap += addr->domain.len + 1;
		break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
	unsigned char buf[cap];
	struct socks4_hdr h = {
		.version = SOCKS4,
		.command = SOCKS4CMD_CONNECT,
		.port = addr->port,
	};
	unsigned char *userid = buf + SOCKS4_HDR_LEN;
	if (idlen > 0) {
		memcpy(userid, proxy->username, idlen + 1);
	} else {
		userid[0] = '\0';
	}
	size_t len = SOCKS4_HDR_LEN + idlen + 1;
	switch (addr->type) {
	case ATYP_INET:
		h.address = read_uint32(&addr->in);
		break;
	case ATYP_INET6: {
		h.address = UINT32_C(0x000000FF);
		char *restrict b = (char *)buf + len;
		if (inet_ntop(AF_INET6, &addr->in6, b, INET6_ADDRSTRLEN) ==
		    NULL) {
			const int err = errno;
			DIALER_LOG_F(
				DEBUG, d, "inet_ntop: (%d) %s", err,
				strerror(err));
			d->err = DIALER_ERR_SYSTEM;
			d->syserr = err;
			return false;
		}
		len += strlen(b) + 1;
	} break;
	case ATYP_DOMAIN: {
		h.address = UINT32_C(0x000000FF);
		unsigned char *restrict b = buf + len;
		const size_t n = addr->domain.len;
		memcpy(b, addr->domain.name, n);
		b[n] = '\0';
		len += n + 1;
	} break;
	}
	socks4hdr_write(buf, &h);
	if (!dialer_send(d, buf, len)) {
		return false;
	}
	LOG_SOCKOPT(
		"socket_rcvlowat",
		socket_rcvlowat(d->w_socket.fd, SOCKS4_RSP_MINLEN));
	return true;
}

static bool send_socks5_authmethod(
	struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE1);
	if (proxy->username == NULL) {
		const unsigned char buf[] = { SOCKS5, 0x01, SOCKS5AUTH_NOAUTH };
		return dialer_send(d, buf, sizeof(buf));
	}
	const unsigned char buf[] = { SOCKS5, 0x02, SOCKS5AUTH_NOAUTH,
				      SOCKS5AUTH_USERPASS };
	return dialer_send(d, buf, sizeof(buf));
}

static bool send_socks5_auth(
	struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE2);
	ASSERT(proxy->username == proxy->credential);
	const size_t ulen = strlen(proxy->username);
	const size_t plen =
		(proxy->password != NULL) ? strlen(proxy->password) : 0;
	if (ulen > UCHAR_MAX || plen > UCHAR_MAX) {
		DIALER_LOG_F(
			ERROR, d, "socks5 credentials too long: %zu, %zu", ulen,
			plen);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return false;
	}
	const size_t len = 1 + 1 + ulen + 1 + plen;
	unsigned char buf[len];
	unsigned char *restrict p = buf;
	/* version */
	*p++ = 0x01;
	*p++ = (unsigned char)ulen;
	if (ulen > 0) {
		(void)memcpy(p, proxy->username, ulen);
	}
	p += ulen;
	*p++ = (unsigned char)plen;
	if (plen > 0) {
		(void)memcpy(p, proxy->password, plen);
	}
	return dialer_send(d, buf, len);
}

static bool
send_socks5_req(struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE3);
	size_t cap = SOCKS5_HDR_LEN;
	switch (addr->type) {
	case ATYP_INET:
		cap += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case ATYP_INET6:
		cap += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	case ATYP_DOMAIN:
		cap += 1 + addr->domain.len + sizeof(in_port_t);
		break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
	unsigned char buf[cap];
	struct socks5_hdr h = {
		.version = SOCKS5,
		.command = SOCKS5CMD_CONNECT,
		.reserved = 0,
	};
	size_t len = SOCKS5_HDR_LEN;
	switch (addr->type) {
	case ATYP_INET: {
		h.addrtype = SOCKS5ADDR_IPV4;
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->in, sizeof(addr->in));
		len += sizeof(addr->in);
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(in_port_t);
	} break;
	case ATYP_INET6: {
		h.addrtype = SOCKS5ADDR_IPV6;
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->in6, sizeof(addr->in6));
		len += sizeof(addr->in6);
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(in_port_t);
	} break;
	case ATYP_DOMAIN: {
		h.addrtype = SOCKS5ADDR_DOMAIN;
		unsigned char *restrict lenbuf = buf + len;
		write_uint8(lenbuf, addr->domain.len);
		len += 1;
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->domain.name, addr->domain.len);
		len += addr->domain.len;
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(in_port_t);
	} break;
	}
	socks5hdr_write(buf, &h);
	if (!dialer_send(d, buf, len)) {
		return false;
	}
	LOG_SOCKOPT(
		"socket_rcvlowat",
		socket_rcvlowat(d->w_socket.fd, SOCKS5_RSP_MINLEN));
	return true;
}

static bool send_dispatch(struct dialer *restrict d)
{
	const struct dialreq *restrict req = d->req;
	const size_t jump = d->jump;
	const size_t next = jump + 1;
	const struct proxyreq *restrict proxy = &req->proxy[jump];
	const struct dialaddr *restrict addr =
		next < req->num_proxy ? &req->proxy[next].addr : &req->addr;
	switch (proxy->proto) {
	case PROTO_HTTP:
		return send_http_req(d, proxy, addr);
	case PROTO_SOCKS4A:
		return send_socks4a_req(d, proxy, addr);
	case PROTO_SOCKS5:
		switch (d->state) {
		case DIALER_STATE_HANDSHAKE1:
			return send_socks5_authmethod(d, proxy);
		case DIALER_STATE_HANDSHAKE2:
			return send_socks5_auth(d, proxy);
		case DIALER_STATE_HANDSHAKE3:
			return send_socks5_req(d, addr);
		default:
			break;
		}
		break;
	default:
		break;
	}
	FAILMSGF("unexpected protocol/state: %d/%d", proxy->proto, d->state);
}

/* Take n bytes -- already peeked by dialer_recv() -- off the socket queue.
 * n is 0 when the parser found no complete unit; a zero-length recv() is not a
 * no-op then, as a drained non-blocking socket fails it with EAGAIN. */
static bool consume_rcvbuf(struct dialer *restrict d, const size_t n)
{
	if (n == 0) {
		return true;
	}
	LOGVV_F("recv: consume %zu bytes", n);
	const int fd = d->w_socket.fd;
	const ssize_t nrecv = recv(fd, d->next, n, 0);
	if (nrecv < 0) {
		const int err = errno;
		DIALER_LOG_F(
			DEBUG, d, "recv: [fd:%d] (%d) %s", fd, err,
			strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return false;
	}
	if ((size_t)nrecv != n) {
		DIALER_LOG_F(DEBUG, d, "recv: [fd:%d] early EOF", fd);
		d->err = DIALER_ERR_EOF;
		d->syserr = 0;
		return false;
	}
	d->next += n;
	if (d->byt_recv != NULL) {
		*d->byt_recv += (uint_least64_t)n;
	}
	return true;
}

static int recv_http_hdr(struct dialer *restrict d)
{
	char *const buf = (char *)d->next;
	char *key, *value;
	char *last = buf, *next;
	for (;;) {
		next = http_parsehdr(last, &key, &value);
		if (next == NULL) {
			DIALER_LOG(DEBUG, d, "http_parsehdr: failed");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		if (next == last) {
			if (!consume_rcvbuf(d, (size_t)(next - buf))) {
				return -1;
			}
			return 1;
		}
		if (key == NULL) {
			break;
		}
		LOGV_F("http: \"%s: %s\"", key, value);
		last = next;
	}

	/* protocol finished */
	if (!consume_rcvbuf(d, (size_t)(next - buf))) {
		return -1;
	}
	return 0;
}

/* Find the end of a complete header block at buf without consuming it, with
 * http_parsehdr's convention: the position past the block, buf itself when the
 * block is incomplete, or NULL on a malformed line. */
static char *scan_http_hdr(char *restrict buf)
{
	char *key, *value;
	for (char *last = buf;;) {
		char *const next = http_parsehdr(last, &key, &value);
		if (next == NULL) {
			return NULL;
		}
		if (next == last) {
			return buf;
		}
		if (key == NULL) {
			return next;
		}
		last = next;
	}
}

/* Parse a status-code token (RFC 9112 4: 3DIGIT); the leading digit is the
 * status class, so a value below 100 is not a status code. */
static bool
parse_status_code(const char *restrict s, uint_fast16_t *restrict out)
{
	if (s[0] < '1' || s[0] > '9' || !isdigit((unsigned char)s[1]) ||
	    !isdigit((unsigned char)s[2]) || s[3] != '\0') {
		return false;
	}
	*out = (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0');
	return true;
}

/* Map a CONNECT response status outside the 2xx range to a dialer error. */
static enum dialer_error http_rsp2err(const uint_fast16_t code)
{
	switch (code) {
	case HTTP_PROXY_AUTHENTICATION_REQUIRED:
		return DIALER_ERR_PROXY_AUTH;
	case HTTP_FORBIDDEN:
		return DIALER_ERR_PROXY_REJECT;
	case HTTP_BAD_GATEWAY:
	case HTTP_SERVICE_UNAVAILABLE:
		return DIALER_ERR_PROXY_REFUSED;
	default:
		break;
	}
	return DIALER_ERR_PROXY_PROTO;
}

static int recv_http_rsp(struct dialer *restrict d)
{
	DIALER_LOG_F(
		DEBUG, d, "state: %d len: %zu cap: %zu", d->state, d->rbuf.len,
		d->rbuf.cap);
	/* dialer_recv() keeps the terminator slot out of the peek window */
	ASSERT(d->rbuf.len < d->rbuf.cap);
	d->rbuf.data[d->rbuf.len] = '\0';
	/* DIALER_STATE_HANDSHAKE2 marks the final response's header block;
	 * until then a status line is expected, interim responses included */
	if (d->state == DIALER_STATE_HANDSHAKE2) {
		return recv_http_hdr(d);
	}
	ASSERT(d->state == DIALER_STATE_HANDSHAKE1);
	for (;;) {
		struct http_message msg;
		char *const buf = (char *)d->next;
		char *const next = http_parse(buf, &msg);
		if (next == NULL) {
			DIALER_LOG(DEBUG, d, "http_parse: failed");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		if (next == buf) {
			return 1;
		}
		if (!http_version_is_1x(msg.rsp.version)) {
			DIALER_LOG_F(
				DEBUG, d, "unsupported HTTP version: %s",
				msg.rsp.version);
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		uint_fast16_t code;
		if (!parse_status_code(msg.rsp.code, &code)) {
			DIALER_LOG_F(
				DEBUG, d, "invalid HTTP status code: %s",
				msg.rsp.code);
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		if (code >= 300) {
			DIALER_LOG_F(
				DEBUG, d, "HTTP: %s %s", msg.rsp.code,
				msg.rsp.status);
			d->err = http_rsp2err(code);
			d->syserr = 0;
			return -1;
		}
		if (code >= 200) {
			/* RFC 9110 9.3.6: any 2xx to CONNECT starts the tunnel */
			if (!consume_rcvbuf(d, (size_t)(next - buf))) {
				return -1;
			}
			d->state = DIALER_STATE_HANDSHAKE2;
			return recv_http_hdr(d);
		}
		/* RFC 9110 15.2: skip any 1xx interim response, whole -- so
		 * consume nothing until its header block has arrived */
		char *const hdrend = scan_http_hdr(next);
		if (hdrend == NULL) {
			DIALER_LOG(DEBUG, d, "http_parsehdr: failed");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		if (hdrend == next) {
			return 1;
		}
		DIALER_LOG_F(
			DEBUG, d, "HTTP interim: %s %s", msg.rsp.code,
			msg.rsp.status);
		if (!consume_rcvbuf(d, (size_t)(hdrend - buf))) {
			return -1;
		}
		/* Each response has its own header limit. Reclaim the consumed
		 * interim prefix, retaining the peeked suffix and terminator. */
		const size_t remaining =
			(size_t)(d->rbuf.data + d->rbuf.len - d->next);
		memmove(d->rbuf.data, d->next, remaining + 1);
		d->rbuf.len = remaining;
		d->next = d->rbuf.data;
	}
}

static int recv_socks4a_rsp(struct dialer *restrict d)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE1);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	const size_t want = SOCKS4_HDR_LEN;
	if (len < want) {
		return (int)(want - len);
	}
	struct socks4_hdr h;
	socks4hdr_read(&h, hdr);
	const uint_fast8_t version = h.version;
	if (version != UINT8_C(0)) {
		DIALER_LOG_F(
			DEBUG, d,
			"unexpected SOCKS4 response version: %" PRIuFAST8,
			version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t command = h.command;
	switch (command) {
	case SOCKS4RSP_GRANTED:
		break;
	case SOCKS4RSP_REJECTED:
		DIALER_LOG(DEBUG, d, "SOCKS4 request rejected or failed");
		d->err = DIALER_ERR_PROXY_REFUSED;
		d->syserr = 0;
		return -1;
	case SOCKS4RSP_NOIDENTD:
		DIALER_LOG(DEBUG, d, "SOCKS4: cannot connect to client identd");
		d->err = DIALER_ERR_PROXY_REJECT;
		d->syserr = 0;
		return -1;
	case SOCKS4RSP_IDENTMISMATCH:
		DIALER_LOG(DEBUG, d, "SOCKS4: identd user-id mismatch");
		d->err = DIALER_ERR_PROXY_AUTH;
		d->syserr = 0;
		return -1;
	default:
		DIALER_LOG_F(
			DEBUG, d, "unsupported SOCKS4 command: %" PRIuFAST8,
			command);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	return 0;
}

static const char *const socks5_errorstr[] = {
	[SOCKS5RSP_SUCCEEDED] = "Succeeded",
	[SOCKS5RSP_FAIL] = "General SOCKS server failure",
	[SOCKS5RSP_NOALLOWED] = "Connection not allowed by ruleset",
	[SOCKS5RSP_NETUNREACH] = "Network unreachable",
	[SOCKS5RSP_HOSTUNREACH] = "Host unreachable",
	[SOCKS5RSP_CONNREFUSED] = "Connection refused",
	[SOCKS5RSP_TTLEXPIRED] = "TTL expired",
	[SOCKS5RSP_CMDNOSUPPORT] = "Command not supported",
	[SOCKS5RSP_ATYPNOSUPPORT] = "Address type not supported",
};

static int recv_socks5_rsp(struct dialer *restrict d)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE3);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	size_t want = SOCKS5_HDR_LEN;
	if (len < want) {
		return (int)(want - len);
	}

	struct socks5_hdr h;
	socks5hdr_read(&h, hdr);
	const uint_fast8_t version = h.version;
	if (version != SOCKS5) {
		DIALER_LOG_F(
			DEBUG, d,
			"unexpected SOCKS5 response version: %" PRIuFAST8,
			version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t command = h.command;
	if (command != SOCKS5RSP_SUCCEEDED) {
		if (command < ARRAY_SIZE(socks5_errorstr)) {
			DIALER_LOG_F(
				DEBUG, d, "SOCKS5: %s",
				socks5_errorstr[command]);
		} else {
			DIALER_LOG_F(
				DEBUG, d,
				"unsupported SOCKS5 command: %" PRIuFAST8,
				command);
		}
		switch (command) {
		case SOCKS5RSP_NOALLOWED:
			d->err = DIALER_ERR_PROXY_REJECT;
			break;
		case SOCKS5RSP_CONNREFUSED:
			d->err = DIALER_ERR_PROXY_REFUSED;
			break;
		default:
			d->err = DIALER_ERR_PROXY_PROTO;
			break;
		}
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t addrtype = h.addrtype;
	switch (addrtype) {
	case SOCKS5ADDR_IPV4:
		want += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_IPV6:
		want += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_DOMAIN: {
		/* BND.ADDR is [len][domain][port]; the length byte follows the
		 * fixed header, so it must be present before sizing the rest */
		if (len < want + 1) {
			return (int)(want + 1 - len);
		}
		const uint_fast8_t domlen = read_uint8(hdr + want);
		want += 1 + (size_t)domlen + sizeof(in_port_t);
		break;
	}
	default:
		DIALER_LOG_F(
			DEBUG, d, "unexpected SOCKS5 addrtype: %" PRIuFAST8,
			addrtype);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	if (len < want) {
		return (int)(want - len);
	}
	/* protocol finished */
	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	return 0;
}

static int recv_socks5_auth(struct dialer *restrict d)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE2);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	const size_t want = 2;
	if (len < want) {
		return (int)(want - len);
	}
	const uint_fast8_t version = read_uint8(hdr + 0);
	const uint_fast8_t status = read_uint8(hdr + 1);
	if (version != 0x01 || status != 0x00) {
		DIALER_LOG_F(
			DEBUG, d,
			"authenticate failed: version=0x%02" PRIxFAST8
			" status=0x%02" PRIxFAST8,
			version, status);
		d->err = DIALER_ERR_PROXY_AUTH;
		d->syserr = 0;
		return -1;
	}
	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	d->state = DIALER_STATE_HANDSHAKE3;
	if (!send_dispatch(d)) {
		return -1;
	}
	return recv_socks5_rsp(d);
}

static int recv_socks5_authmethod(struct dialer *restrict d)
{
	ASSERT(d->state == DIALER_STATE_HANDSHAKE1);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	size_t want = SOCKS5_AUTH_RSP_LEN;
	if (len < want) {
		return (int)(want - len);
	}
	struct socks5_auth_rsp ar;
	socks5authrsp_read(&ar, hdr);
	const uint_fast8_t version = ar.version;
	if (version != SOCKS5) {
		DIALER_LOG_F(
			DEBUG, d, "unsupported SOCKS5 version: %" PRIuFAST8,
			version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t method = ar.method;

	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	switch (method) {
	case SOCKS5AUTH_NOAUTH:
		d->state = DIALER_STATE_HANDSHAKE3;
		if (!send_dispatch(d)) {
			return -1;
		}
		return recv_socks5_rsp(d);
	case SOCKS5AUTH_USERPASS:
		/* Only NOAUTH is offered when we have no credentials; a server
		 * selecting USERPASS here picked a method we never advertised.
		 * Acting on it would deref a NULL username in send_socks5_auth. */
		if (d->req->proxy[d->jump].username == NULL) {
			DIALER_LOG(
				DEBUG, d,
				"SOCKS5: server selected an auth method that was not offered");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		d->state = DIALER_STATE_HANDSHAKE2;
		if (!send_dispatch(d)) {
			return -1;
		}
		return recv_socks5_auth(d);
	case SOCKS5AUTH_NOACCEPTABLE:
		DIALER_LOG(DEBUG, d, "SOCKS5 auth: method negotiation failed");
		d->err = DIALER_ERR_PROXY_AUTH;
		d->syserr = 0;
		return -1;
	default:
		break;
	}
	DIALER_LOG_F(
		DEBUG, d,
		"SOCKS5: unexpected auth method %" PRIuFAST8
		" (protocol error?)",
		method);
	d->err = DIALER_ERR_PROXY_PROTO;
	d->syserr = 0;
	return -1;
}

static int
recv_dispatch(struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	switch (proxy->proto) {
	case PROTO_HTTP:
		return recv_http_rsp(d);
	case PROTO_SOCKS4A:
		return recv_socks4a_rsp(d);
	case PROTO_SOCKS5:
		switch (d->state) {
		case DIALER_STATE_HANDSHAKE1:
			return recv_socks5_authmethod(d);
		case DIALER_STATE_HANDSHAKE2:
			return recv_socks5_auth(d);
		case DIALER_STATE_HANDSHAKE3:
			return recv_socks5_rsp(d);
		default:
			break;
		}
		break;
	default:
		break;
	}
	FAILMSGF("unexpected protocol/state: %d/%d", proxy->proto, d->state);
}

/* The bytes a peek may place at d->next. MSG_PEEK restarts at the socket-queue
 * head and writes into d->next, so the window is the buffer space from d->next
 * to the end -- cap minus the consumed offset, not cap minus rbuf.len -- less
 * the last byte, kept free for the terminator recv_http_rsp() writes. A peek
 * returns whatever is queued, which past a final reply includes the tunnel's
 * first bytes, so a full window says nothing about the reply's length: that is
 * judged by whether the parser still wants more than the window can hold. */
static size_t rbuf_window(const struct dialer *restrict d)
{
	return d->rbuf.cap - (size_t)(d->next - d->rbuf.data) - 1;
}

static int dialer_recv(struct dialer *restrict d)
{
	const int fd = d->w_socket.fd;
	unsigned char *buf = d->next;
	const size_t n = rbuf_window(d);
	ssize_t nrecv;
	do {
		nrecv = recv(fd, buf, n, MSG_PEEK);
	} while (nrecv < 0 && errno == EINTR);
	if (nrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 1;
		}
		DIALER_LOG_F(
			DEBUG, d, "recv: [fd:%d] (%d) %s", fd, err,
			strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return -1;
	}
	if (nrecv == 0) {
		DIALER_LOG_F(DEBUG, d, "recv: [fd:%d] early EOF", fd);
		d->err = DIALER_ERR_EOF;
		d->syserr = 0;
		return -1;
	}
	const int sockerr = socket_get_error(fd);
	if (sockerr != 0) {
		if (sockerr == EINTR || sockerr == EAGAIN ||
		    sockerr == EWOULDBLOCK) {
			return 1;
		}
		DIALER_LOG_F(
			DEBUG, d, "recv: [fd:%d] (%d) %s", fd, sockerr,
			strerror(sockerr));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = sockerr;
		return -1;
	}
	/* a re-peek re-reads bytes already counted in rbuf.len, so recompute the
	 * total relative to `buf` (== d->next) instead of accumulating nrecv */
	d->rbuf.len = (size_t)(buf - d->rbuf.data) + (size_t)nrecv;
	LOG_BIN_F(
		VERYVERBOSE, buf, (size_t)nrecv, 0, "recv: %zu bytes",
		(size_t)nrecv);

	const int ret = recv_dispatch(d, &d->req->proxy[d->jump]);
	if (ret < 0) {
		return ret;
	}
	if (ret == 0) {
		/* restore default */
		LOG_SOCKOPT(
			"socket_rcvlowat", socket_rcvlowat(d->w_socket.fd, 1));
		return 0;
	}
	const size_t want = (d->rbuf.data + d->rbuf.len) - d->next + ret;
	/* want counts from d->next, so bound it by the peek window: a larger
	 * SO_RCVLOWAT could never be met by a peek, and the dial would stall */
	if (want > rbuf_window(d)) {
		DIALER_LOG(DEBUG, d, "recv: header too long");
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	LOG_SOCKOPT("socket_rcvlowat", socket_rcvlowat(fd, (int)want));
	return 1;
}

/* core of the dialer state machine: the proxy handshakes (EV_READ). The
 * connection that carries them is established by the attempts (EV_WRITE),
 * which hand their winning socket over here. */
static void socket_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;

	ASSERT(d->state == DIALER_STATE_HANDSHAKE1 ||
	       d->state == DIALER_STATE_HANDSHAKE2 ||
	       d->state == DIALER_STATE_HANDSHAKE3);
	const int ret = dialer_recv(d);
	if (ret < 0) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
	if (ret > 0) {
		return;
	}

	/* handshake done, advance to the next hop */
	d->rbuf.len = 0;
	d->next = d->rbuf.data;
	d->jump++;

	if (d->jump >= d->req->num_proxy) {
		d->dialed_fd = fd;
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}

	d->state = DIALER_STATE_HANDSHAKE1;
	if (!send_dispatch(d)) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
}

/* Delay before a connection attempt that has neither succeeded nor failed is
 * joined by the next address's, the "Connection Attempt Delay" of RFC 8305 5
 * at the value that document recommends: long enough that a healthy first
 * address usually wins the dial on its own, short enough that an address
 * silently dropping the SYN does not hold the whole dial for a TCP timeout. */
#define DIALER_ATTEMPT_DELAY 0.25

/* Open a socket for one address and start connecting it. Returns the socket,
 * or -1 with d->err set when this address cannot be tried at all. */
static int
attempt_open(struct dialer *restrict d, const struct sockaddr *restrict sa)
{
	const int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGD_F("socket: (%d) %s", err, strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return -1;
	}

	/* both setters return the errno; they never set the global one */
	int setup_err = socket_set_cloexec(fd);
	if (setup_err == 0) {
		setup_err = socket_set_nonblock(fd);
	}
	if (setup_err != 0) {
		socket_close(fd);
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = setup_err;
		return -1;
	}
	const struct config *restrict conf = d->conf;
#if WITH_NETDEVICE
	if (conf->netdev != NULL) {
		socket_bind_netdev(fd, conf->netdev);
	}
#endif
	/* best-effort tuning; failure does not affect correctness */
	LOG_SOCKOPT(
		"socket_set_tcp",
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive));
#if WITH_TCP_KEEPALIVE_PARAMS
	if (conf->tcp_keepalive) {
		socket_set_keepalive(
			fd, conf->tcp_keepidle, conf->tcp_keepintvl,
			conf->tcp_keepcnt);
	}
#endif
	LOG_SOCKOPT(
		"socket_set_buffer",
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf));
#if WITH_TCP_FASTOPEN_CONNECT
	if (conf->tcp_fastopen_connect) {
		/* opportunistic; falls back to a normal handshake on failure */
		LOG_SOCKOPT(
			"socket_set_fastopen_connect",
			socket_set_fastopen_connect(fd, true));
	}
#endif
	if (LOGLEVEL(VERBOSE)) {
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), sa);
		LOG_F(VERBOSE, "connect %s", addr_str);
	}
	if (connect(fd, sa, sa_len(sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			/* only at DEBUG: another address may still carry the
			 * dial, and the owner logs the failure that ends it */
			if (LOGLEVEL(DEBUG)) {
				char addr_str[64];
				sa_format(addr_str, sizeof(addr_str), sa);
				LOG_F(DEBUG, "connect %s: (%d) %s", addr_str,
				      err, strerror(err));
			}
			d->err = DIALER_ERR_CONNECT;
			d->syserr = err;
			socket_close(fd);
			return -1;
		}
	}
	/* connect() may also have succeeded outright -- a loopback peer, or TCP
	 * Fast Open deferring the handshake to the first send. The socket is
	 * reported writable either way, so both paths meet in attempt_cb(). */
	return fd;
}

/* Start connecting to the next address, passing over the ones the egress
 * policy blocks and the ones that cannot be tried. Returns false once the
 * addresses are exhausted, having started no further attempt. */
static bool attempt_next(struct dialer *restrict d, struct ev_loop *loop)
{
	while (d->next_addr < d->num_addr) {
		const size_t i = d->next_addr++;
		const struct sockaddr *restrict sa = &d->addr[i].sa;
		if (!check_outbound_sa(d->conf, sa)) {
			/* the policy bars this address, not the destination:
			 * carry on to the next, and report a blocked dial only
			 * if no address is left to report anything else */
			if (d->err == DIALER_OK) {
				d->err = DIALER_ERR_BLOCKED;
				d->syserr = 0;
			}
			continue;
		}
		const int fd = attempt_open(d, sa);
		if (fd < 0) {
			continue;
		}
		ev_io *restrict w = &d->w_attempt[i];
		ev_io_set(w, fd, EV_WRITE);
		ev_io_start(loop, w);
		d->num_inflight++;
		if (d->next_addr < d->num_addr) {
			/* let the next address join this attempt once it has
			 * had the delay to itself */
			ev_timer_again(loop, &d->w_delay);
		} else {
			ev_timer_stop(loop, &d->w_delay);
		}
		return true;
	}
	ev_timer_stop(loop, &d->w_delay);
	return false;
}

/* One attempt has connected: it takes the dial, and the others are dropped. */
static void
attempt_win(struct dialer *restrict d, struct ev_loop *loop, const int fd)
{
	/* the losers have nothing left to win, and the handshake wants the
	 * dialer's one socket watcher to itself */
	attempt_stop(d, loop, fd);
	/* an address that failed before this one recorded its error; the dial
	 * is not failing after all */
	d->err = DIALER_OK;
	d->syserr = 0;

	if (d->req->num_proxy == 0) {
		d->dialed_fd = fd;
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}

	/* install fd on the watcher before dispatching: send_dispatch() sends
	 * the first handshake through d->w_socket.fd; on failure dialer_stop()
	 * closes it (dialed_fd is still -1) */
	d->state = DIALER_STATE_HANDSHAKE1;
	ev_io_set(&d->w_socket, fd, EV_READ);
	if (!send_dispatch(d)) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
	ev_io_start(loop, &d->w_socket);
}

/* connection establishment (EV_WRITE), one watcher per address in flight */
static void attempt_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct dialer *restrict d = watcher->data;
	ASSERT(d->state == DIALER_STATE_CONNECT);
	const int fd = watcher->fd;

	const int sockerr = socket_get_error(fd);
	if (sockerr == 0) {
		attempt_win(d, loop, fd);
		return;
	}

	if (LOGLEVEL(DEBUG)) {
		/* each attempt watches the address of the same index */
		const size_t i = (size_t)(watcher - d->w_attempt);
		ASSERT(i < d->num_addr);
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), &d->addr[i].sa);
		LOG_F(DEBUG, "connect %s: (%d) %s", addr_str, sockerr,
		      strerror(sockerr));
	}
	ev_io_stop(loop, watcher);
	ev_io_set(watcher, -1, EV_NONE);
	socket_close(fd);
	d->num_inflight--;
	d->err = DIALER_ERR_CONNECT;
	d->syserr = sockerr;

	/* RFC 8305 5: a failed attempt hands its turn to the next address at
	 * once, rather than leaving it to wait out the delay */
	if (!attempt_next(d, loop) && d->num_inflight == 0) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
	}
}

/* the running attempts have had their delay; let the next address race them */
static void
attempt_delay_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct dialer *restrict d = watcher->data;
	ASSERT(d->state == DIALER_STATE_CONNECT);
	if (!attempt_next(d, loop) && d->num_inflight == 0) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
	}
}

/* Begin connecting: the first address is tried at once and the rest follow it
 * as the delay elapses or an attempt fails. Returns false when not one attempt
 * could be started, d->err telling which address failed how. */
static bool connect_start(struct dialer *restrict d, struct ev_loop *loop)
{
	ASSERT(d->num_addr > 0);
	d->state = DIALER_STATE_CONNECT;
	d->next_addr = 0;
	d->num_inflight = 0;
	return attempt_next(d, loop);
}

static void resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *ctx,
	const union sockaddr_max *restrict addr, const size_t num_addr)
{
	struct dialer *restrict d = ctx;
	ASSERT(q == d->resolve_query);
	(void)q;
	d->resolve_query = NULL;

	const struct dialaddr *restrict dialaddr =
		d->req->num_proxy > 0 ? &d->req->proxy[0].addr : &d->req->addr;
	if (num_addr == 0) {
		LOG_TXT(DEBUG, dialaddr->domain.name, dialaddr->domain.len,
			"name resolution failed:");
		d->err = DIALER_ERR_RESOLVE;
		d->syserr = 0;
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}

	/* the name carries the port for every address it resolved to */
	ASSERT(num_addr <= ARRAY_SIZE(d->addr));
	for (size_t i = 0; i < num_addr; i++) {
		d->addr[i] = addr[i];
		switch (d->addr[i].sa.sa_family) {
		case AF_INET:
			d->addr[i].in.sin_port = htons(dialaddr->port);
			break;
		case AF_INET6:
			d->addr[i].in6.sin6_port = htons(dialaddr->port);
			break;
		default:
			FAILMSGF(
				"unexpected address family: %d",
				d->addr[i].sa.sa_family);
		}
	}
	d->num_addr = num_addr;

	if (LOGLEVEL(DEBUG)) {
		char node_str[DIALADDR_STRLEN + 1];
		const int n =
			dialaddr_format(node_str, sizeof(node_str), dialaddr);
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), &d->addr[0].sa);
		LOG_TXT_F(
			DEBUG, node_str, n > 0 ? (size_t)n : 0, 0,
			"resolve: %s", addr_str);
	}

	if (!connect_start(d, loop)) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
}

/* Reset the per-dial state so a dialer can be re-driven by another dialer_do()
 * without a fresh dialer_init(). The watchers, callback, and byte counters set
 * up once by dialer_init() are left intact. */
static void dialer_reset(struct dialer *restrict d)
{
	d->req = NULL;
	d->resolve_query = NULL;
	d->jump = 0;
	d->state = DIALER_STATE_INIT;
	d->err = DIALER_OK;
	d->syserr = 0;
	d->w_socket.fd = -1;
	d->dialed_fd = -1;
	d->num_addr = 0;
	d->next_addr = 0;
	d->num_inflight = 0;
	for (size_t i = 0; i < ARRAY_SIZE(d->w_attempt); i++) {
		d->w_attempt[i].fd = -1;
	}
	d->next = d->rbuf.data;
	BUF_INIT(d->rbuf, 0);
}

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *const byt_sent, uint_least64_t *const byt_recv)
{
	ev_io_init(&d->w_socket, socket_cb, -1, EV_NONE);
	d->w_socket.data = d;
	for (size_t i = 0; i < ARRAY_SIZE(d->w_attempt); i++) {
		ev_io_init(&d->w_attempt[i], attempt_cb, -1, EV_NONE);
		d->w_attempt[i].data = d;
	}
	ev_timer_init(
		&d->w_delay, attempt_delay_cb, DIALER_ATTEMPT_DELAY,
		DIALER_ATTEMPT_DELAY);
	d->w_delay.data = d;
	ev_init(&d->w_finish, finish_cb);
	d->w_finish.data = d;

	d->finish_cb = *callback;
	d->byt_sent = byt_sent;
	d->byt_recv = byt_recv;
	dialer_reset(d);
}

static void dialer_start(struct dialer *restrict d, struct ev_loop *loop)
{
	const struct dialreq *restrict req = d->req;
	const struct dialaddr *restrict addr =
		req->num_proxy > 0 ? &req->proxy[0].addr : &req->addr;

	switch (addr->type) {
	case ATYP_INET: {
		d->addr[0].in = (struct sockaddr_in){
			.sin_family = AF_INET,
			.sin_addr = addr->in,
			.sin_port = htons(addr->port),
		};
		d->num_addr = 1;
		if (!connect_start(d, loop)) {
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
	} break;
	case ATYP_INET6: {
		d->addr[0].in6 = (struct sockaddr_in6){
			.sin6_family = AF_INET6,
			.sin6_addr = addr->in6,
			.sin6_port = htons(addr->port),
		};
		d->num_addr = 1;
		if (!connect_start(d, loop)) {
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
	} break;
	case ATYP_DOMAIN: {
		char host[FQDN_MAX_LENGTH + 1];
		memcpy(host, addr->domain.name, addr->domain.len);
		host[addr->domain.len] = '\0';
		d->state = DIALER_STATE_RESOLVE;
		struct resolve_query *restrict q = resolve_do(
			d->resolver,
			(struct resolve_cb){
				.func = resolve_cb,
				.data = d,
			},
			host, NULL, d->conf->resolve_pf);
		if (q == NULL) {
			/* resolve_do() fails only on OOM */
			d->err = DIALER_ERR_SYSTEM;
			d->syserr = ENOMEM;
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
		d->resolve_query = q;
	} break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
}

/* dialaddr_parse() refuses an address the dialer cannot dial, but a front end
 * builds a struct dialaddr from the wire instead: socks.c keeps the client's
 * DST.ADDR and DST.PORT verbatim so the ruleset decides on the request as
 * sent. Refuse the dial here, where every address of the request is known and
 * no byte of it has reached a peer yet. */
static bool
check_dialaddr(struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	if (addr->port == 0) {
		/* RFC 6335 6 reserves port 0: no TCP peer answers there */
		LOGD("no port to dial");
		d->err = DIALER_ERR_BADADDR;
		d->syserr = 0;
		return false;
	}
	if (addr->type == ATYP_DOMAIN &&
	    !is_host_name(addr->domain.name, addr->domain.len)) {
		LOG_TXT(DEBUG, addr->domain.name, addr->domain.len,
			"not a host name:");
		d->err = DIALER_ERR_BADADDR;
		d->syserr = 0;
		return false;
	}
	return true;
}

static bool check_request(struct dialer *restrict d)
{
	const struct dialreq *restrict req = d->req;
	for (size_t i = 0; i < req->num_proxy; i++) {
		if (!check_dialaddr(d, &req->proxy[i].addr)) {
			return false;
		}
	}
	return check_dialaddr(d, &req->addr);
}

void dialer_do(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct dialreq *restrict req, const struct config *restrict conf,
	struct resolver *restrict resolver, struct server *restrict server)
{
	if (LOGLEVEL(VERBOSE)) {
		char s[4096];
		const int r = dialreq_format(s, sizeof(s), req);
		ASSERT(r > 0);
		LOG_TXT_F(
			VERBOSE, s, r > 0 ? (size_t)r : 0, 0,
			"dialer [%p]: request start", (void *)req);
	}

	dialer_reset(d);
	d->req = req;
	d->conf = conf;
	d->resolver = resolver;
	d->start_ns = (int_least64_t)clock_monotonic_ns();
	d->server = server;
	if (!check_request(d)) {
		ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
	dialer_start(d, loop);
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	if (d->state == DIALER_STATE_DONE) {
		return;
	}
	LOGD_F("dialer [%p]: request cancelled", (void *)d->req);

	d->err = DIALER_CANCELLED;
	d->syserr = 0;
	dialer_stop(d, loop);
	ev_clear_pending(loop, &d->w_finish);
}
