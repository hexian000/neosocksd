#ifndef CONF_H
#define CONF_H

#include "sockutil.h"

struct config {
	const char *forward;
#if WITH_NETDEVICE
	const char *netdev;
#endif
	int resolve_pf;
#if WITH_REUSEPORT
	bool reuseport : 1;
#endif
#if WITH_TPROXY
	bool transparent : 1;
#endif
	bool traceback : 1;
	double timeout;
};

#endif /* CONF_H */
