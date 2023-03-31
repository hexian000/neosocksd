#include "util.h"

#include <unistd.h>
#include <pwd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

void drop_privileges(const char *user)
{
	if (getuid() != 0) {
		return;
	}
	if (user == NULL) {
		LOGW("running as root, please consider using \"-u\"");
		return;
	}
	if (chdir("/") != 0) {
		const int err = errno;
		LOGW_F("chdir: %s", strerror(err));
	}
	struct passwd *restrict pwd = getpwnam(user);
	if (pwd == NULL) {
		LOGW_F("su: user \"%s\" does not exist ", user);
		return;
	}
	if (pwd->pw_uid == 0) {
		return;
	}
	LOGI_F("su: user=%s uid=%jd gid=%jd", user, (intmax_t)pwd->pw_uid,
	       (intmax_t)pwd->pw_gid);
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(err));
	}
#endif
	if (setgid(pwd->pw_gid) != 0 || setegid(pwd->pw_gid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop group privileges: %s", strerror(err));
	}
	if (setuid(pwd->pw_uid) != 0 || seteuid(pwd->pw_uid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop user privileges: %s", strerror(err));
	}
}
