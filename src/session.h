/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SESSION_H
#define SESSION_H

struct ev_loop;
struct session;

typedef void (*session_closer)(struct ev_loop *loop, struct session *ss);

struct session {
	struct session *prev, *next;
	session_closer close;
};

void session_add(struct session *ss);
void session_del(struct session *ss);
void session_closeall(struct ev_loop *loop);

#endif /* SESSION_H */
