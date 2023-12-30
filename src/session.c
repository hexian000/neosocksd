/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "session.h"
#include "utils/slog.h"
#include "util.h"

#include <stddef.h>

void session_add(struct session *restrict ss)
{
	ss->prev = NULL;
	ss->next = G.sessions;
	if (G.sessions != NULL) {
		G.sessions->prev = ss;
	}
	G.sessions = ss;
}

void session_del(struct session *restrict ss)
{
	struct session *restrict prev = ss->prev;
	struct session *restrict next = ss->next;
	if (prev != NULL) {
		prev->next = next;
	} else {
		G.sessions = next;
	}
	if (next != NULL) {
		next->prev = prev;
	}
}

void session_closeall(struct ev_loop *loop)
{
	size_t num = 0;
	for (struct session *ss = G.sessions; ss != NULL; ss = G.sessions) {
		ss->close(loop, ss);
		num++;
	}
	LOGI_F("%zu sessions closed", num);
}
