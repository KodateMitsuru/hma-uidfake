#ifndef _FAKE_RCUPDATE_H
#define _FAKE_RCUPDATE_H
#include <linux/types.h>
/* host-test shim: single-threaded, so no grace period is ever waited for */
#define __rcu
#define rcu_dereference(p) (p)
#define rcu_access_pointer(p) (p)
#define rcu_dereference_protected(p, c) ((void)(c), (p))
#define rcu_assign_pointer(p, v) \
	do {                     \
		(p) = (v);       \
	} while (0)
#define rcu_read_lock() \
	do {            \
	} while (0)
#define rcu_read_unlock() \
	do {              \
	} while (0)
#define synchronize_rcu() \
	do {              \
	} while (0)
#endif
