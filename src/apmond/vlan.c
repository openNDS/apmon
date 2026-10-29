/*
 * VLAN of a bridge port (an AP interface or a wired port), without forking:
 * 1. vlan_filtering bridge: the port's PVID (else its only untagged VLAN), from one rtnetlink
 *    AF_BRIDGE dump with RTEXT_FILTER_BRVLAN (what "bridge vlan show" prints). This is how
 *    netifd attaches an AP whose network is br-lan.10 (option network lan, lan on br-lan.10).
 * 2. bridge without vlan_filtering (eg mesh11sd or classic setups, br-guest with port eth0.20):
 *    the VLAN of the bridge itself (br-x.N) or of its one 802.1q port.
 * The dump is cached for 5 minutes, and refreshed early (at most every 30 s) for an unknown port.
 *
 * VXLAN (mesh11sd's trunk: "ip link add vxlan<tun_id> type vxlan id <vni> ..." added to bridge
 * br-tun<tun_id>): a port that is a vxlan device, or a port of a bridge that has a vxlan port,
 * carries {"vni": N, "device": "vxlan<tun_id>"}. From a second rtnetlink dump (IFLA_MASTER,
 * IFLA_INFO_KIND "vxlan", IFLA_VXLAN_ID), cached with the VLAN data.
 */
#include <errno.h>
#include <limits.h>
#include <linux/if_bridge.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "apmond.h"

#define VLAN_CACHE_MS (300 * 1000)
#define VLAN_RETRY_MS (30 * 1000)
#define MAX_PORTS 64
#define MAX_PORT_VLANS 32

struct port_vlan {
	int ifindex;
	int vid;
};

struct link_info {
	int ifindex;
	int master;
	uint32_t vni;
	int is_vxlan;
	char name[IFNAMSIZ];
};

static struct port_vlan ports[MAX_PORTS];
static struct link_info links[MAX_PORTS];
static int link_count;
static int port_count;
static uint64_t dumped_ms;
static int dumped;

/* One RTM_NEWLINK of the AF_BRIDGE dump: remember the port's access VLAN */
static void parse_link(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct rtattr *rta;
	int len = (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*ifi));
	uint16_t flags[MAX_PORT_VLANS];
	uint16_t vids[MAX_PORT_VLANS];
	int count = 0;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		struct rtattr *sub;
		int sublen;

		if (rta->rta_type != IFLA_AF_SPEC) {
			continue;
		}
		sublen = (int)RTA_PAYLOAD(rta);
		for (sub = RTA_DATA(rta); RTA_OK(sub, sublen); sub = RTA_NEXT(sub, sublen)) {
			struct bridge_vlan_info *info;

			if (sub->rta_type != IFLA_BRIDGE_VLAN_INFO) {
				continue;
			}
			if (RTA_PAYLOAD(sub) < sizeof(*info) || count >= MAX_PORT_VLANS) {
				continue;
			}
			info = RTA_DATA(sub);
			flags[count] = info->flags;
			vids[count] = info->vid;
			count++;
		}
	}

	if (count == 0 || port_count >= MAX_PORTS) {
		return;
	}
	ports[port_count].ifindex = ifi->ifi_index;
	ports[port_count].vid = apmon_port_access_vlan(flags, vids, count);
	port_count++;
}

/* IFLA_LINKINFO: is it a vxlan device, and its VNI */
static void parse_linkinfo(struct rtattr *info, struct link_info *l)
{
	struct rtattr *sub;
	int len = (int)RTA_PAYLOAD(info);
	struct rtattr *data = NULL;

	for (sub = RTA_DATA(info); RTA_OK(sub, len); sub = RTA_NEXT(sub, len)) {
		if (sub->rta_type == IFLA_INFO_KIND && strcmp((char *)RTA_DATA(sub), "vxlan") == 0) {
			l->is_vxlan = 1;
		}
		if (sub->rta_type == IFLA_INFO_DATA) {
			data = sub;
		}
	}
	if (!l->is_vxlan || data == NULL) {
		return;
	}
	len = (int)RTA_PAYLOAD(data);
	for (sub = RTA_DATA(data); RTA_OK(sub, len); sub = RTA_NEXT(sub, len)) {
		if (sub->rta_type == IFLA_VXLAN_ID && RTA_PAYLOAD(sub) >= sizeof(uint32_t)) {
			l->vni = *(uint32_t *)RTA_DATA(sub);
		}
	}
}

/* One RTM_NEWLINK of the plain link dump: name, master bridge, vxlan */
static void parse_any_link(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct rtattr *rta;
	int len = (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*ifi));
	struct link_info *l;

	if (link_count >= MAX_PORTS) {
		return;
	}
	l = &links[link_count];
	memset(l, 0, sizeof(*l));
	l->ifindex = ifi->ifi_index;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == IFLA_IFNAME) {
			snprintf(l->name, sizeof(l->name), "%s", (char *)RTA_DATA(rta));
		}
		if (rta->rta_type == IFLA_MASTER && RTA_PAYLOAD(rta) >= sizeof(uint32_t)) {
			l->master = (int)*(uint32_t *)RTA_DATA(rta);
		}
		if (rta->rta_type == IFLA_LINKINFO) {
			parse_linkinfo(rta, l);
		}
	}
	link_count++;
}

static void dump_links(int family, void (*handler)(struct nlmsghdr *nh))
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
		char attrs[16];
	} req;
	struct rtattr *rta;
	char buf[16384];
	int fd;
	int done = 0;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		return;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifi));
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.ifi.ifi_family = (unsigned char)family;
	rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = IFLA_EXT_MASK;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	*(uint32_t *)RTA_DATA(rta) = RTEXT_FILTER_BRVLAN;
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;

	if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
		close(fd);
		return;
	}

	while (!done) {
		struct nlmsghdr *nh;
		ssize_t n = recv(fd, buf, sizeof(buf), 0);

		if (n <= 0) {
			break;
		}
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned int)n); nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			if (nh->nlmsg_type == RTM_NEWLINK) {
				handler(nh);
			}
		}
	}
	close(fd);
}

static void dump_bridge_vlans(void)
{
	port_count = 0;
	link_count = 0;
	dump_links(AF_BRIDGE, parse_link);
	dump_links(AF_UNSPEC, parse_any_link);
}

static int filtering_port_vlan(int ifindex, uint64_t now_ms, int *found)
{
	int i;

	*found = 0;
	if (!dumped || now_ms - dumped_ms >= VLAN_CACHE_MS) {
		dump_bridge_vlans();
		dumped = 1;
		dumped_ms = now_ms;
	}
	for (i = 0; i < port_count; i++) {
		if (ports[i].ifindex == ifindex) {
			*found = 1;
			return ports[i].vid;
		}
	}
	/* A port added since the last dump (eg an AP that came up): refresh, but not every cycle */
	if (now_ms - dumped_ms >= VLAN_RETRY_MS) {
		dump_bridge_vlans();
		dumped_ms = now_ms;
		for (i = 0; i < port_count; i++) {
			if (ports[i].ifindex == ifindex) {
				*found = 1;
				return ports[i].vid;
			}
		}
	}
	return 0;
}

/* The bridge a port belongs to, from the /sys/class/net/<port>/master link */
static int port_master(const char *port, char *master, size_t len)
{
	char path[128];
	char target[PATH_MAX];
	ssize_t n;
	const char *slash;

	snprintf(path, sizeof(path), "/sys/class/net/%s/master", port);
	n = readlink(path, target, sizeof(target) - 1);
	if (n <= 0) {
		return -1;
	}
	target[n] = '\0';
	slash = strrchr(target, '/');
	if (slash == NULL) {
		slash = target;
	} else {
		slash++;
	}
	snprintf(master, len, "%s", slash);
	return 0;
}

static int bridge_filters_vlans(const char *bridge)
{
	char path[128];
	char text[8];
	FILE *f;
	int on = 0;

	snprintf(path, sizeof(path), "/sys/class/net/%s/bridge/vlan_filtering", bridge);
	f = fopen(path, "r");
	if (f == NULL) {
		return 0;
	}
	if (fgets(text, sizeof(text), f) != NULL) {
		on = atoi(text) == 1;
	}
	fclose(f);
	return on;
}

/* Bridge without vlan_filtering: its own .N, else the one 802.1q port it has */
static int plain_bridge_vlan(const char *bridge)
{
	char path[128];
	int vid = apmon_vlan_from_name(bridge);
	int found = 0;
	FILE *p;
	struct if_nameindex *names;
	struct if_nameindex *it;

	if (vid > 0) {
		return vid;
	}
	names = if_nameindex();
	if (names == NULL) {
		return 0;
	}
	for (it = names; it->if_index != 0; it++) {
		char master[IFNAMSIZ];
		int v;

		if (port_master(it->if_name, master, sizeof(master)) != 0) {
			continue;
		}
		if (strcmp(master, bridge) != 0) {
			continue;
		}
		snprintf(path, sizeof(path), "/proc/net/vlan/%s", it->if_name);
		p = fopen(path, "r");
		if (p == NULL) {
			continue;
		}
		fclose(p);
		v = apmon_vlan_from_name(it->if_name);
		if (v > 0 && v != vid) {
			vid = v;
			found++;
		}
	}
	if_freenameindex(names);
	if (found == 1) {
		return vid;
	}
	return 0;
}

int apmond_port_vlan(const char *port, uint64_t now_ms)
{
	char master[IFNAMSIZ];
	int ifindex;
	int found;
	int vid;

	if (port == NULL || port[0] == '\0') {
		return 0;
	}
	if (port_master(port, master, sizeof(master)) != 0) {
		return 0;
	}
	if (bridge_filters_vlans(master)) {
		ifindex = (int)if_nametoindex(port);
		if (ifindex <= 0) {
			return 0;
		}
		vid = filtering_port_vlan(ifindex, now_ms, &found);
		return vid;
	}
	return plain_bridge_vlan(master);
}

static struct link_info *find_link(int ifindex)
{
	int i;

	for (i = 0; i < link_count; i++) {
		if (links[i].ifindex == ifindex) {
			return &links[i];
		}
	}
	return NULL;
}

/*
 * VXLAN behind a port: the port itself, else a vxlan port of the same bridge (mesh11sd br-tun<N>).
 * Returns 1 and fills vni and device, 0 when it does not apply.
 */
int apmond_port_vxlan(const char *port, uint64_t now_ms, uint32_t *vni, char *device, size_t device_len)
{
	struct link_info *self;
	int found;
	int i;

	if (port == NULL || port[0] == '\0') {
		return 0;
	}
	/* refreshes the cache when due */
	filtering_port_vlan((int)if_nametoindex(port), now_ms, &found);

	self = find_link((int)if_nametoindex(port));
	if (self == NULL) {
		return 0;
	}
	if (self->is_vxlan) {
		*vni = self->vni;
		snprintf(device, device_len, "%s", self->name);
		return 1;
	}
	if (self->master == 0) {
		return 0;
	}
	for (i = 0; i < link_count; i++) {
		if (links[i].master != self->master || !links[i].is_vxlan) {
			continue;
		}
		*vni = links[i].vni;
		snprintf(device, device_len, "%s", links[i].name);
		return 1;
	}
	return 0;
}
