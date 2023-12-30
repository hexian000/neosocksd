/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_parser.h"
#include "http_server.h"
#include "utils/debug.h"
#include "conf.h"
#include "server.h"
#include "ruleset.h"

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	if (ctx->uplink.state == XFER_FINISHED ||
	    ctx->downlink.state == XFER_FINISHED) {
		http_ctx_close(loop, ctx);
		return;
	}
	if (ctx->state == STATE_CONNECTED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		ctx->state = STATE_ESTABLISHED;
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		HTTP_CTX_LOG_F(
			INFO, ctx, "established, %zu active",
			stats->num_sessions);
		ev_timer_stop(loop, &ctx->w_timeout);
		return;
	}
}

void http_ctx_hijack(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);

	HTTP_CTX_LOG(DEBUG, ctx, "connected");
	/* cleanup before state change */
	dialreq_free(ctx->dialreq);

	struct server_stats *restrict stats = &ctx->s->stats;
	if (G.conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
	} else {
		ev_timer_stop(loop, &ctx->w_timeout);
		ctx->state = STATE_ESTABLISHED;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		HTTP_CTX_LOG_F(
			INFO, ctx, "established, %zu active",
			stats->num_sessions);
	}

	const struct event_cb cb = {
		.cb = xfer_state_cb,
		.ctx = ctx,
	};
	transfer_init(
		&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static struct dialreq *make_dialreq(const char *addr_str)
{
#if WITH_RULESET
	struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		return ruleset_resolve(ruleset, addr_str);
	}
#endif
	struct dialreq *req = dialreq_new(0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	if (!dialaddr_set(&req->addr, addr_str, strlen(addr_str))) {
		dialreq_free(req);
		return NULL;
	}
	return req;
}

void http_handle_proxy(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->parser.msg;
	if (strcmp(msg->req.method, "CONNECT") != 0) {
		http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
		return;
	}
	HTTP_CTX_LOG_F(DEBUG, ctx, "http: CONNECT \"%s\"", msg->req.url);

	struct dialreq *req = make_dialreq(msg->req.url);
	if (req == NULL) {
		http_resp_errpage(&ctx->parser, HTTP_BAD_GATEWAY);
		return;
	}
	ctx->dialreq = req;
	ctx->state = STATE_CONNECT;
	dialer_start(&ctx->dialer, loop, req);
}
