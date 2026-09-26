// SPDX-License-Identifier: GPL-2.0
/*
 * netlink.c - policy injection channel from privileged userspace into the kernel.
 *
 * Protocol (little endian, matches src/tools/netlink.cpp):
 *   KAUX_CMD_SET:  attr KAUX_ATTR_BLOB = u32 npairs, then npairs * (caller, target)
 *                  caller == 0 means "any caller"
 *   KAUX_CMD_PING: no payload, ACK only
 *   KAUX_CMD_APK:  attr KAUX_ATTR_BLOB = u32 n, then n * (st_dev, ino_lo, ino_hi, uid)
 */
#include "uidfake.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h> /* LINUX_VERSION_CODE for the resv_start_op guard */
#include <net/genetlink.h>

#define KAUX_FAMILY_NAME "kaux"
#define KAUX_FAMILY_VERSION 1

enum { KAUX_ATTR_UNSPEC, KAUX_ATTR_BLOB, __KAUX_ATTR_MAX };
#define KAUX_ATTR_MAX (__KAUX_ATTR_MAX - 1)

enum { KAUX_CMD_UNSPEC, KAUX_CMD_SET, KAUX_CMD_PING, KAUX_CMD_APK, __KAUX_CMD_MAX };
#define KAUX_CMD_MAX (__KAUX_CMD_MAX - 1)

#define MAX_BLOB_BYTES 32768

static int kaux_set(struct sk_buff *skb, struct genl_info *info)
{
	const u32 *p;
	u32 len, npairs;

	if (!info->attrs[KAUX_ATTR_BLOB])
		return -EINVAL;
	p = nla_data(info->attrs[KAUX_ATTR_BLOB]);
	len = nla_len(info->attrs[KAUX_ATTR_BLOB]);
	if (len < 4 || (len & 3) || len > MAX_BLOB_BYTES)
		return -EINVAL;

	/* blob: u32 npairs, then npairs * (caller, target uid); caller = 0 means any */
	npairs = p[0];
	if ((unsigned long long)len < 4ull + 8ull * npairs)
		return -EINVAL;

	pr_info("uidfake: netlink policy: %u pair(s)\n", npairs);
	policy_apply(p + 1, npairs);
	return 0;
}

/*
 * The apk inodes of the apps that have rules: u32 n, then n * (dev, ino_lo, ino_hi, uid).
 * Read in userspace, where package names live; the kernel only compares the numbers.
 */
static int kaux_apk(struct sk_buff *skb, struct genl_info *info)
{
	const u32 *p;
	u32 len, n;

	if (!info->attrs[KAUX_ATTR_BLOB])
		return -EINVAL;
	p = nla_data(info->attrs[KAUX_ATTR_BLOB]);
	len = nla_len(info->attrs[KAUX_ATTR_BLOB]);
	if (len < 4 || (len & 3) || len > MAX_BLOB_BYTES)
		return -EINVAL;
	n = p[0];
	if ((unsigned long long)len < 4ull + 16ull * (unsigned long long)n)
		return -EINVAL;
	pr_info("uidfake: netlink apk inodes: %u entr(ies)\n", n);
	return uidfake_apk_apply(p + 1, n);
}

static int kaux_ping(struct sk_buff *skb, struct genl_info *info)
{
	/* A command id that lands here instead of where it belongs would otherwise look like a
	 * success, because a ping is answered with an ACK like anything else. */
	pr_info("uidfake: netlink ping\n");
	return 0;
}

/*
 *
 * The helper builds this from /proc: an app and the isolated processes it spawns share one
 * category layout is baked in here, the map is simply what the helper measured.
 */

static const struct genl_ops kaux_ops[] = {
    {.cmd = KAUX_CMD_SET, .flags = GENL_ADMIN_PERM, .doit = kaux_set},
    {.cmd = KAUX_CMD_PING, .flags = GENL_ADMIN_PERM, .doit = kaux_ping},
    {.cmd = KAUX_CMD_APK, .flags = GENL_ADMIN_PERM, .doit = kaux_apk},
};

static const struct genl_multicast_group kaux_mcgrps[] = {{.name = "events"}};

static struct genl_family kaux_family = {
    .name = KAUX_FAMILY_NAME,
    .version = KAUX_FAMILY_VERSION,
    .maxattr = KAUX_ATTR_MAX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    .resv_start_op = KAUX_CMD_MAX + 1,
#endif
    .module = THIS_MODULE,
    .ops = kaux_ops,
    .n_ops = ARRAY_SIZE(kaux_ops),
    .mcgrps = kaux_mcgrps,
    .n_mcgrps = ARRAY_SIZE(kaux_mcgrps),
};

int netlink_init(void)
{
	int rc = genl_register_family(&kaux_family);
	pr_info("uidfake: netlink family '%s' register rc=%d\n", KAUX_FAMILY_NAME, rc);
	return rc;
}

void netlink_exit(void) { genl_unregister_family(&kaux_family); }
