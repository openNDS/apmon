/*
 * Factory (label) MAC address: the node id. mesh11sd 8.0.0 does not link libapmon
 * (apmond stays optional); it has its own mesh11sd_factory_mac() with the same
 * chain, and the two are kept in agreement by shared test vectors, so both give a
 * node the same id, even on a board where the chain picks the wrong MAC.
 * Also apmon_ifindex_action: when the collector re-binds its listener.
 * No OpenWrt libraries, so it is unit tested on the host against a fake root tree.
 *
 * Order (as mesh11sd get_factory_mac):
 *  1. device tree: /sys/firmware/devicetree/base/aliases/label-mac-device
 *     (else /proc/device-tree/..., else the copy the init script makes in
 *     /tmp/apmond/devicetree before the jail starts: newer ujail mounts an empty
 *     tmpfs over /sys/firmware) names a node; its mac-address, else
 *     local-mac-address (6 binary bytes)
 *  2. /etc/board.json system.label_macaddr
 *  3. /etc/config/system option label_macaddr in the first "config system"
 *     section (a user override)
 *  4. the permanent MAC of the WAN device; the caller passes the name
 *     (apmond asks netifd over ubus); NULL or "" skips this step
 *  5. the first of eth1 eth0 lan0 lan1 with a universally administered permanent MAC
 *  6. the lowest ifindex ARPHRD_ETHER device with a universally administered permanent MAC
 * Nothing else: no br-lan fallback. If all fail, the caller must refuse to run.
 *
 * Permanent MAC: ETHTOOL_GPERMADDR, else /sys/class/net/<dev>/address when
 * addr_assign_type is 0 (NET_ADDR_PERM). mesh11sd rewrites the current MAC of some
 * interfaces (eth1, br-lan), so the current MAC is never used and the id does not
 * depend on whether mesh11sd ran first.
 * An all-zero MAC counts as none everywhere; locally administered MACs are refused
 * at steps 5 and 6.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "apmon.h"

/* device tree copy made by the init script before ujail hides /sys/firmware */
#define APMON_DT_COPY "/tmp/apmond/devicetree"

static int mac_is_zero(const uint8_t mac[APMON_ID_LEN])
{
	int i;

	for (i = 0; i < APMON_ID_LEN; i++) {
		if (mac[i] != 0) {
			return 0;
		}
	}
	return 1;
}

static int mac_is_local(const uint8_t mac[APMON_ID_LEN])
{
	if (mac[0] & 0x02) {
		return 1;
	}
	return 0;
}

static int read_text(const char *path, char *out, size_t len)
{
	FILE *f = fopen(path, "r");
	size_t n;

	if (f == NULL) {
		return -1;
	}
	n = fread(out, 1, len - 1, f);
	fclose(f);
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == '\0')) {
		n--;
		out[n] = '\0';
	}
	return 0;
}

/* SIOCETHTOOL ETHTOOL_GPERMADDR; needs no capability */
int apmon_ethtool_permaddr(const char *dev, uint8_t out[APMON_ID_LEN])
{
	struct {
		struct ethtool_perm_addr hdr;
		uint8_t data[32];
	} req;
	struct ifreq ifr;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}
	memset(&req, 0, sizeof(req));
	req.hdr.cmd = ETHTOOL_GPERMADDR;
	req.hdr.size = sizeof(req.data);
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
	ifr.ifr_data = (void *)&req;
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	if (ret != 0) {
		return -1;
	}
	if (req.hdr.size != APMON_ID_LEN) {
		return -1;
	}
	memcpy(out, req.data, APMON_ID_LEN);
	return 0;
}

/* Tests replace this; NULL skips the ioctl and uses sysfs only */
int (*apmon_permaddr_fn)(const char *dev, uint8_t out[APMON_ID_LEN]) = apmon_ethtool_permaddr;

/* Permanent MAC of <dev>: ethtool, else sysfs address if addr_assign_type is 0 */
static int iface_perm_mac(const char *root, const char *dev, uint8_t out[APMON_ID_LEN])
{
	char path[256];
	char text[32];

	if (dev == NULL || dev[0] == '\0' || strchr(dev, '/') != NULL) {
		return -1;
	}
	if (strlen(dev) >= IFNAMSIZ) {
		return -1;
	}
	snprintf(path, sizeof(path), "%s/sys/class/net/%s", root, dev);
	if (access(path, F_OK) != 0) {
		return -1;
	}
	if (apmon_permaddr_fn != NULL) {
		if (apmon_permaddr_fn(dev, out) == 0 && !mac_is_zero(out)) {
			return 0;
		}
	}
	snprintf(path, sizeof(path), "%s/sys/class/net/%s/addr_assign_type", root, dev);
	if (read_text(path, text, sizeof(text)) != 0) {
		return -1;
	}
	if (strcmp(text, "0") != 0) {
		return -1;
	}
	snprintf(path, sizeof(path), "%s/sys/class/net/%s/address", root, dev);
	if (read_text(path, text, sizeof(text)) != 0) {
		return -1;
	}
	if (apmon_mac_parse(text, out) != 0) {
		return -1;
	}
	if (mac_is_zero(out)) {
		return -1;
	}
	return 0;
}

static int iface_universal_mac(const char *root, const char *dev, uint8_t out[APMON_ID_LEN])
{
	if (iface_perm_mac(root, dev, out) != 0) {
		return -1;
	}
	if (mac_is_local(out)) {
		return -1;
	}
	return 0;
}

/* 1. device tree label-mac-device in one device tree root: mac-address, else local-mac-address */
static int dt_label_mac_in(const char *root, const char *base, uint8_t out[APMON_ID_LEN])
{
	static const char *const props[] = { "mac-address", "local-mac-address" };
	char node[200];
	char path[512];
	size_t i;

	snprintf(path, sizeof(path), "%s%s/aliases/label-mac-device", root, base);
	if (read_text(path, node, sizeof(node)) != 0) {
		return -1;
	}
	if (node[0] == '\0') {
		return -1;
	}
	for (i = 0; i < sizeof(props) / sizeof(props[0]); i++) {
		FILE *f;
		size_t n;

		snprintf(path, sizeof(path), "%s%s%s/%s", root, base, node, props[i]);
		f = fopen(path, "rb");
		if (f == NULL) {
			continue;
		}
		n = fread(out, 1, APMON_ID_LEN, f);
		fclose(f);
		if (n == APMON_ID_LEN && !mac_is_zero(out)) {
			return 0;
		}
	}
	return -1;
}

static int dt_label_mac(const char *root, uint8_t out[APMON_ID_LEN])
{
	if (dt_label_mac_in(root, "/sys/firmware/devicetree/base", out) == 0) {
		return 0;
	}
	if (dt_label_mac_in(root, "/proc/device-tree", out) == 0) {
		return 0;
	}
	return dt_label_mac_in(root, APMON_DT_COPY, out);
}

/* Parse "xx:xx:xx:xx:xx:xx" at p (17 characters), refusing zero */
static int parse_mac17(const char *p, uint8_t out[APMON_ID_LEN])
{
	char mac[18];

	memcpy(mac, p, 17);
	mac[17] = '\0';
	if (apmon_mac_parse(mac, out) != 0) {
		return -1;
	}
	if (mac_is_zero(out)) {
		return -1;
	}
	return 0;
}

/* 2. "label_macaddr": "xx:xx:xx:xx:xx:xx" in board.json (only ever under "system") */
static int board_label_mac(const char *root, uint8_t out[APMON_ID_LEN])
{
	char path[256];
	char *buf;
	char *p;
	char *q;
	FILE *f;
	size_t n;
	int ret = -1;

	snprintf(path, sizeof(path), "%s/etc/board.json", root);
	f = fopen(path, "r");
	if (f == NULL) {
		return -1;
	}
	buf = malloc(65536);
	if (buf == NULL) {
		fclose(f);
		return -1;
	}
	n = fread(buf, 1, 65535, f);
	fclose(f);
	buf[n] = '\0';

	p = strstr(buf, "\"label_macaddr\"");
	if (p != NULL) {
		p += strlen("\"label_macaddr\"");
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') {
			p++;
		}
		if (*p == '"') {
			p++;
			q = strchr(p, '"');
			if (q != NULL && q - p == 17) {
				if (parse_mac17(p, out) == 0) {
					ret = 0;
				}
			}
		}
	}
	free(buf);
	return ret;
}

/* 3. option label_macaddr in the first "config system" section of /etc/config/system */
static int uci_label_mac(const char *root, uint8_t out[APMON_ID_LEN])
{
	char path[256];
	char line[256];
	FILE *f;
	int in_system = 0;
	int seen_system = 0;
	int ret = -1;

	snprintf(path, sizeof(path), "%s/etc/config/system", root);
	f = fopen(path, "r");
	if (f == NULL) {
		return -1;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line;
		char *v;
		size_t len;

		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (strncmp(p, "config", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) {
			if (seen_system) {
				break;
			}
			v = p + 6;
			while (*v == ' ' || *v == '\t') {
				v++;
			}
			if (strncmp(v, "system", 6) == 0) {
				in_system = 1;
				seen_system = 1;
			}
			continue;
		}
		if (!in_system) {
			continue;
		}
		if (strncmp(p, "option", 6) != 0) {
			continue;
		}
		p += 6;
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (strncmp(p, "label_macaddr", 13) != 0) {
			continue;
		}
		p += 13;
		if (*p != ' ' && *p != '\t') {
			continue;
		}
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (*p == '\'' || *p == '"') {
			p++;
		}
		len = strlen(p);
		if (len < 17) {
			continue;
		}
		if (parse_mac17(p, out) == 0) {
			ret = 0;
		}
		break;
	}
	fclose(f);
	return ret;
}

/* 6. lowest ifindex with type 1 (ARPHRD_ETHER) and a universally administered permanent MAC */
static int first_ether_mac(const char *root, uint8_t out[APMON_ID_LEN], char *name, size_t name_len)
{
	char path[512];
	char text[32];
	DIR *d;
	struct dirent *e;
	long best = -1;

	snprintf(path, sizeof(path), "%s/sys/class/net", root);
	d = opendir(path);
	if (d == NULL) {
		return -1;
	}
	while ((e = readdir(d)) != NULL) {
		uint8_t mac[APMON_ID_LEN];
		long ifindex;

		if (e->d_name[0] == '.') {
			continue;
		}
		snprintf(path, sizeof(path), "%s/sys/class/net/%s/type", root, e->d_name);
		if (read_text(path, text, sizeof(text)) != 0) {
			continue;
		}
		if (strcmp(text, "1") != 0) {
			continue;
		}
		snprintf(path, sizeof(path), "%s/sys/class/net/%s/ifindex", root, e->d_name);
		if (read_text(path, text, sizeof(text)) != 0) {
			continue;
		}
		ifindex = strtol(text, NULL, 10);
		if (best >= 0 && ifindex >= best) {
			continue;
		}
		if (iface_universal_mac(root, e->d_name, mac) != 0) {
			continue;
		}
		best = ifindex;
		memcpy(out, mac, APMON_ID_LEN);
		snprintf(name, name_len, "%s", e->d_name);
	}
	closedir(d);
	if (best < 0) {
		return -1;
	}
	return 0;
}

int apmon_factory_mac(const char *root, const char *wan_device,
		      uint8_t out[APMON_ID_LEN], char *source, size_t source_len)
{
	static const char *const common[] = { "eth1", "eth0", "lan0", "lan1" };
	char name[256];
	size_t i;

	if (root == NULL) {
		root = "";
	}
	if (dt_label_mac(root, out) == 0) {
		snprintf(source, source_len, "device tree label-mac-device");
		return 0;
	}
	if (board_label_mac(root, out) == 0) {
		snprintf(source, source_len, "board.json label_macaddr");
		return 0;
	}
	if (uci_label_mac(root, out) == 0) {
		snprintf(source, source_len, "system.@system[0].label_macaddr");
		return 0;
	}
	if (iface_perm_mac(root, wan_device, out) == 0) {
		snprintf(source, source_len, "wan device %s permanent MAC", wan_device);
		return 0;
	}
	for (i = 0; i < sizeof(common) / sizeof(common[0]); i++) {
		if (iface_universal_mac(root, common[i], out) == 0) {
			snprintf(source, source_len, "fallback interface %s permanent MAC", common[i]);
			return 0;
		}
	}
	if (first_ether_mac(root, out, name, sizeof(name)) == 0) {
		snprintf(source, source_len, "first ethernet interface %s permanent MAC", name);
		return 0;
	}
	snprintf(source, source_len, "none");
	return -1;
}

int apmon_ifindex_action(int bound, int now)
{
	if (now <= 0) {
		return APMON_IFINDEX_GONE;
	}
	if (now == bound) {
		return APMON_IFINDEX_SAME;
	}
	return APMON_IFINDEX_REBIND;
}
