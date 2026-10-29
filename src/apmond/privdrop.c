/*
 * apmond 2.x - run as an unprivileged user without ujail.
 * Where the kernel has no PID/IPC/UTS namespaces (small targets such as ramips/mt76x8),
 * ujail cannot start, and procd's own user switch would drop every capability. So the
 * init script starts "apmond run -u apmond" as root and apmond drops to that user itself,
 * keeping only CAP_NET_ADMIN (adding and removing its ULA addresses over netlink), as
 * dnsmasq does with its own user switch.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>

#include "apmond.h"

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#endif

/* Keep only CAP_NET_ADMIN in the bounding set (needs root's CAP_SETPCAP, so before setuid) */
static void drop_bounding_set(void)
{
	int cap;

	for (cap = 0; cap <= 63; cap++) {
		if (cap == CAP_NET_ADMIN) {
			continue;
		}
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno == EINVAL) {
			/* past the last capability this kernel knows */
			break;
		}
	}
}

static int set_net_admin_only(void)
{
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct data[2];

	memset(&header, 0, sizeof(header));
	memset(data, 0, sizeof(data));
	header.version = _LINUX_CAPABILITY_VERSION_3;
	header.pid = 0;
	data[0].effective = 1u << CAP_NET_ADMIN;
	data[0].permitted = 1u << CAP_NET_ADMIN;
	data[0].inheritable = 1u << CAP_NET_ADMIN;

	if (syscall(SYS_capset, &header, data) != 0) {
		return -1;
	}
	/* ambient: the swconfig speed fallback (popen) runs with the same rights */
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0);
	return 0;
}

/* Returns 0 when running as user with CAP_NET_ADMIN only, -1 (with a log line) otherwise */
int apmond_drop_privileges(const char *user)
{
	struct passwd *pw;
	gid_t gid;

	if (geteuid() != 0) {
		return 0;
	}
	pw = getpwnam(user);
	if (pw == NULL) {
		LOG_ERR_("user %s not found, running as root", user);
		return -1;
	}
	gid = pw->pw_gid;

	drop_bounding_set();
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
		LOG_ERR_("cannot keep capabilities: %s", strerror(errno));
		return -1;
	}
	if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(pw->pw_uid) != 0) {
		LOG_ERR_("cannot switch to user %s: %s", user, strerror(errno));
		return -1;
	}
	if (set_net_admin_only() != 0) {
		LOG_ERR_("cannot keep CAP_NET_ADMIN: %s", strerror(errno));
		return -1;
	}
	prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	return 0;
}
