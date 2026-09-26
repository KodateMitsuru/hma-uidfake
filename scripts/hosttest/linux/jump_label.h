#ifndef _FAKE_JUMP_LABEL_H
#define _FAKE_JUMP_LABEL_H
/* host-test shim: no jump labels, the diagnostic branch is simply never taken */
struct static_key_false {
	int enabled;
};
#define static_branch_unlikely(key) (0)
#define static_branch_enable(key)                                                                  \
	do {                                                                                       \
	} while (0)
#define static_branch_disable(key)                                                                 \
	do {                                                                                       \
	} while (0)
#define static_key_enabled(key) (0)
#endif
