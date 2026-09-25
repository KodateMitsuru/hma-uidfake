#ifndef _FAKE_USER_H
#define _FAKE_USER_H
#include <linux/types.h>
struct user_struct { u32 uid; };
static inline bool host_uid_live(u32 u) { return u >= 10000 && u < 20000; }
static inline struct user_struct *host_find(u32 u) { static struct user_struct s; if (host_uid_live(u)) { s.uid = u; return &s; } return 0; }
static inline struct user_struct *find_user(kuid_t u) { return host_find((u32)u); }
static inline void free_uid(struct user_struct *u) { (void)u; }
#define KUIDT_INIT(x) ((kuid_t)(x))
#endif
