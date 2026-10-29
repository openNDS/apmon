/*
 * apmond ULA addresses, ported from apmond 1.x (manage_ula / claim_router_ula):
 * - prefix and subnet derived from the passphrase (apmon_ula_prefix), so every node computes them
 * - every node: <prefix>:<subnet>:<EUI-64 of the device MAC>/64 on option device
 * - the collector: <prefix>:<subnet>::1/64, first come wins:
 *     not a collector candidate      -> never hold ::1 (peer)
 *     holding ::1 and DAD failed     -> drop it, back off
 *     ::1 answers (another collector) -> back off
 *     backed off and ::1 silent for router_takeover_misses checks -> take over
 *     first claim after a random 0..claim_delay_max s delay, then wait for DAD
 * - addresses are added and removed with rtnetlink (no ip command); all are removed on stop
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "apmond.h"

#define IFA_TENTATIVE 0x40
#define IFA_DADFAILED 0x08

static struct in6_addr node_addr;
static struct in6_addr router_addr;
static int have_prefix;
static int added_node;
static int added_router;
static int misses;
static int claim_delay_done;
static int backed_off;

/* ---------- rtnetlink address add/delete ---------- */

static int addr_change(int add, const struct in6_addr *addr, int ifindex)
{
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		char attrs[64];
	} req;
	struct rtattr *rta;
	struct sockaddr_nl sa;
	char reply[1024];
	struct nlmsghdr *nh;
	int fd;
	int ret = -1;
	ssize_t n;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add) {
		req.nh.nlmsg_type = RTM_NEWADDR;
		req.nh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	} else {
		req.nh.nlmsg_type = RTM_DELADDR;
	}
	req.ifa.ifa_family = AF_INET6;
	req.ifa.ifa_prefixlen = 64;
	req.ifa.ifa_index = (unsigned int)ifindex;

	rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = IFA_LOCAL;
	rta->rta_len = RTA_LENGTH(sizeof(*addr));
	memcpy(RTA_DATA(rta), addr, sizeof(*addr));
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	n = recv(fd, reply, sizeof(reply), 0);
	if (n > 0) {
		nh = (struct nlmsghdr *)reply;
		if (nh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = NLMSG_DATA(nh);

			if (err->error == 0) {
				ret = 0;
			} else if (add && err->error == -EEXIST) {
				ret = 0;
			}
		}
	}
	close(fd);
	return ret;
}

/*
 * Look the address up in /proc/net/if_inet6.
 * Returns -1 if absent, else the kernel's address flags (tentative 0x40, dadfailed 0x08).
 */
static int addr_flags(const struct in6_addr *addr)
{
	FILE *f = fopen("/proc/net/if_inet6", "r");
	char want[33];
	char line[256];
	int flags = -1;

	if (f == NULL) {
		return -1;
	}
	apmon_hex_encode(addr->s6_addr, 16, want);

	while (fgets(line, sizeof(line), f) != NULL) {
		char hex[33];
		unsigned int ifindex;
		unsigned int plen;
		unsigned int scope;
		unsigned int fl;
		char name[IFNAMSIZ + 1];

		if (sscanf(line, "%32s %x %x %x %x %16s", hex, &ifindex, &plen, &scope, &fl, name) != 6) {
			continue;
		}
		if (strcmp(hex, want) == 0 && strcmp(name, apmond.cfg.netdev) == 0) {
			flags = (int)fl;
			break;
		}
	}
	fclose(f);
	return flags;
}

static void addr_text(const struct in6_addr *addr, char *out, size_t len)
{
	inet_ntop(AF_INET6, addr, out, (socklen_t)len);
}

static int add_address(const struct in6_addr *addr)
{
	char text[INET6_ADDRSTRLEN];
	int ifindex = (int)if_nametoindex(apmond.cfg.netdev);

	addr_text(addr, text, sizeof(text));
	if (ifindex == 0) {
		LOG_ERR_("device [ %s ] not found, cannot assign ULA addresses", apmond.cfg.netdev);
		return -1;
	}
	if (addr_flags(addr) >= 0) {
		return 0;
	}
	if (addr_change(1, addr, ifindex) != 0) {
		LOG_ERR_("failed to add ULA address %s/64 to %s", text, apmond.cfg.netdev);
		return -1;
	}
	LOG_NOTICE_("ULA address %s/64 added to %s", text, apmond.cfg.netdev);
	return 0;
}

static void del_address(const struct in6_addr *addr)
{
	char text[INET6_ADDRSTRLEN];
	int ifindex = (int)if_nametoindex(apmond.cfg.netdev);

	if (ifindex == 0 || addr_flags(addr) < 0) {
		return;
	}
	addr_text(addr, text, sizeof(text));
	if (addr_change(0, addr, ifindex) == 0) {
		LOG_NOTICE_("ULA address %s/64 deleted from %s", text, apmond.cfg.netdev);
	}
}

/* Is another collector answering on <ula>::1? (1.x pinged it; a TCP connect to our port says the same) */
static int router_answers(void)
{
	struct sockaddr_in6 sa;
	struct pollfd pfd;
	int fd;
	int answered = 0;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return 0;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons((uint16_t)apmond.cfg.port);
	sa.sin6_addr = router_addr;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		answered = 1;
	} else if (errno == EINPROGRESS) {
		pfd.fd = fd;
		pfd.events = POLLOUT;
		if (poll(&pfd, 1, 1000) == 1) {
			int err = 0;
			socklen_t len = sizeof(err);

			getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
			/* refused also means something holds the address, but not apmond: treat as in use */
			if (err == 0 || err == ECONNREFUSED) {
				answered = 1;
			}
		}
	}
	close(fd);
	return answered;
}

/* ---------- public ---------- */

int apmond_ula_init(const char *passphrase)
{
	uint8_t prefix[8];
	uint8_t iid[8];

	if (apmon_ula_prefix(passphrase, prefix) != 0) {
		return -1;
	}
	apmon_eui64_iid(apmond.id, iid);

	memset(&router_addr, 0, sizeof(router_addr));
	memcpy(router_addr.s6_addr, prefix, 8);
	router_addr.s6_addr[15] = 1;

	memcpy(node_addr.s6_addr, prefix, 8);
	memcpy(node_addr.s6_addr + 8, iid, 8);

	addr_text(&node_addr, apmond.node_ula, sizeof(apmond.node_ula));
	addr_text(&router_addr, apmond.router_ula, sizeof(apmond.router_ula));
	have_prefix = 1;
	return 0;
}

static void set_reason(const char *fmt, const char *arg)
{
	char reason[sizeof(apmond.role_reason)];

	snprintf(reason, sizeof(reason), fmt, arg);
	if (strcmp(reason, apmond.role_reason) != 0) {
		snprintf(apmond.role_reason, sizeof(apmond.role_reason), "%s", reason);
		LOG_NOTICE_("%s", reason);
	}
}

static int drop_router(const char *fmt)
{
	del_address(&router_addr);
	added_router = 0;
	misses = 0;
	backed_off = 1;
	set_reason(fmt, apmond.router_ula);
	return 0;
}

/*
 * Called every interval. candidate = this node may be the collector (upstream gateway or role collector).
 * Returns 1 if this node holds <ula>::1 (is the collector), 0 otherwise.
 */
int apmond_ula_tick(int candidate)
{
	int flags;
	int i;

	if (!have_prefix) {
		return candidate;
	}

	if (add_address(&node_addr) == 0) {
		added_node = 1;
	}

	if (!candidate) {
		misses = 0;
		backed_off = 0;
		if (addr_flags(&router_addr) >= 0) {
			del_address(&router_addr);
			added_router = 0;
		}
		set_reason("peer: no upstream gateway%s", "");
		return 0;
	}

	flags = addr_flags(&router_addr);
	if (flags >= 0) {
		if (flags & IFA_DADFAILED) {
			return drop_router("DAD failed on %s after claiming - another collector holds it");
		}
		misses = 0;
		backed_off = 0;
		set_reason("collector: upstream gateway detected and %s claimed", apmond.router_ula);
		return 1;
	}

	if (router_answers()) {
		misses = 0;
		backed_off = 1;
		set_reason("backed off: %s is already in use by another collector", apmond.router_ula);
		return 0;
	}

	if (backed_off) {
		misses++;
		if (misses < apmond.cfg.router_takeover_misses) {
			LOG_INFO_("%s not answering (%d/%d), waiting before takeover", apmond.router_ula, misses,
				  apmond.cfg.router_takeover_misses);
			return 0;
		}
		LOG_NOTICE_("%s not answering for %d checks, taking over", apmond.router_ula, misses);
	}

	if (!claim_delay_done) {
		uint32_t r = 0;

		claim_delay_done = 1;
		apmon_random(&r, sizeof(r));
		if (apmond.cfg.claim_delay_max > 0) {
			sleep(r % (uint32_t)(apmond.cfg.claim_delay_max + 1));
		}
		if (router_answers()) {
			backed_off = 1;
			set_reason("backed off: %s claimed by another collector during the startup delay", apmond.router_ula);
			return 0;
		}
	}

	if (add_address(&router_addr) != 0) {
		backed_off = 1;
		set_reason("backed off: failed to add %s", apmond.router_ula);
		return 0;
	}
	added_router = 1;

	/* wait for DAD (default one probe, 1 s) */
	for (i = 0; i < 3; i++) {
		flags = addr_flags(&router_addr);
		if (flags < 0 || (flags & IFA_TENTATIVE) == 0 || (flags & IFA_DADFAILED) != 0) {
			break;
		}
		sleep(1);
	}

	flags = addr_flags(&router_addr);
	if (flags >= 0 && (flags & IFA_DADFAILED)) {
		return drop_router("DAD failed on %s - another collector holds it");
	}

	misses = 0;
	backed_off = 0;
	set_reason("collector: upstream gateway detected and %s claimed", apmond.router_ula);
	return 1;
}

int apmond_ula_holding_router(void)
{
	int flags;

	if (!have_prefix) {
		return 0;
	}
	flags = addr_flags(&router_addr);
	return flags >= 0 && (flags & (IFA_DADFAILED | IFA_TENTATIVE)) == 0;
}

/* Our node ULA is present and past DAD, so it can be used as a source address */
int apmond_ula_node_ready(void)
{
	int flags;

	if (!have_prefix) {
		return 0;
	}
	flags = addr_flags(&node_addr);
	return flags >= 0 && (flags & (IFA_DADFAILED | IFA_TENTATIVE)) == 0;
}

void apmond_ula_cleanup(void)
{
	if (!have_prefix) {
		return;
	}
	if (added_router || addr_flags(&router_addr) >= 0) {
		del_address(&router_addr);
	}
	if (added_node || addr_flags(&node_addr) >= 0) {
		del_address(&node_addr);
	}
	added_router = 0;
	added_node = 0;
}
