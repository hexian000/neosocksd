#include "http_impl.h"
#include "conf.h"
#include "ruleset.h"

#include "utils/check.h"
#include <ev.h>

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	if (ctx->uplink.state == XFER_CLOSED ||
	    ctx->downlink.state == XFER_CLOSED) {
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
			LOG_LEVEL_INFO, ctx, "established, %zu active",
			stats->num_sessions);
		ev_timer_stop(loop, &ctx->w_timeout);
		return;
	}
}

void http_ctx_hijack(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);

	HTTP_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "connected");
	/* cleanup before state change */
	free(ctx->dialreq);

	const struct config *restrict conf = G.conf;
	struct server_stats *restrict stats = &ctx->s->stats;
	if (conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
	} else {
		ev_timer_stop(loop, &ctx->w_timeout);
		ctx->state = STATE_ESTABLISHED;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		HTTP_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "established, %zu active",
			stats->num_sessions);
	}

	struct event_cb cb = {
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
	struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		return ruleset_resolve(ruleset, addr_str);
	}

	struct dialaddr addr;
	if (!dialaddr_set(&addr, addr_str, strlen(addr_str))) {
		return NULL;
	}
	struct dialreq *req = dialreq_new(&addr, 0);
	if (req == NULL) {
		LOGOOM();
	}
	return req;
}

void http_handle_proxy(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_message *restrict hdr = &ctx->http_msg;
	if (strcmp(hdr->req.method, "CONNECT") != 0) {
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return;
	}
	HTTP_CTX_LOG_F(
		LOG_LEVEL_DEBUG, ctx, "http: CONNECT \"%s\"", hdr->req.url);

	struct dialreq *req = make_dialreq(hdr->req.url);
	if (req == NULL) {
		http_resp_errpage(ctx, HTTP_BAD_GATEWAY);
		return;
	}
	ctx->dialreq = req;
	ctx->state = STATE_CONNECT;
	dialer_start(&ctx->dialer, loop, req);
}
