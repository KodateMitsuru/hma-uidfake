// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>

#include "uidfake.h"

static int __init uidfake_init(void)
{
	rwlock_init(&policy_lock);
	if (policy_init())
		return -ENOMEM;

	netlink_init();
	pr_info("uidfake: ready (%d hook(s))\n", hooks_install());
	return 0;
}

static void __exit uidfake_exit(void)
{
	netlink_exit();
	hooks_remove();
	policy_free();
	pr_info("uidfake: unloaded\n");
}

module_init(uidfake_init);
module_exit(uidfake_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("local");
MODULE_DESCRIPTION("uidfake - kernel-side uid existence guard (netlink-injected policy)");
