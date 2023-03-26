#include "util.h"

#include <unistd.h>
#include <pwd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

void print_bin(const void *data, const size_t n)
{
	const uint8_t *restrict b = data;
	for (size_t i = 0; i < n; i += 16) {
		fprintf(stderr, "%p: ", (void *)(b + i));
		for (size_t j = 0; j < 16; j++) {
			if ((i + j) < n) {
				fprintf(stderr, "%02" PRIX8 " ", b[i + j]);
			} else {
				fprintf(stderr, "   ");
			}
		}
		fprintf(stderr, " ");
		for (size_t j = 0; j < 16; j++) {
			if ((i + j) < n) {
				if (b[i + j] >= 32 && b[i + j] <= 127) {
					fprintf(stderr, "%c", (char)b[i + j]);
				} else {
					fprintf(stderr, ".");
				}
			} else {
				fprintf(stderr, " ");
			}
		}
		fprintf(stderr, "\n");
	}
	fflush(stderr);
}

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
