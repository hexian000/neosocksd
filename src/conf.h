#ifndef CONF_H
#define CONF_H

#include "sockutil.h"

struct config {
	const char *forward;
	int resolve_pf;
	bool reuseport;
#if WITH_TPROXY
	bool transparent;
#endif
	double timeout;
};

#endif /* CONF_H */
