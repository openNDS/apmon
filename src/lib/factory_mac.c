/*
 * Factory (label) MAC address: the node id, as apmond 1.x get_factory_mac and mesh11sd.
 * No OpenWrt libraries, so it is unit tested on the host against a fake root tree.
 *
 * Order (1.x get_factory_mac, then the 1.x get_device_mac fallback):
 *  1. get_mac_label (/lib/functions/system.sh):
 *     a. device tree: /proc/device-tree/aliases/label-mac-device names a node,
 *        its mac-address, else local-mac-address (6 binary bytes)
 *     b. /etc/board.json system.label_macaddr
 *  2. the MAC of uci network.wan.device (the caller passes the device name)
 *  3. the first of eth1 eth0 lan0 lan1 that exists
 *  4. the first interface of type ether (ARPHRD_ETHER), lowest ifindex
 *  5. the fallback device (option device, br-lan)
 * Interface MACs come from /sys/class/net/<dev>/address. An all-zero MAC counts as none.
 * mesh11sd rewrites the MAC of br-lan, but none of these, so the id is the same
 * with mesh11sd running or not.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

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

/* /sys/class/net/<dev>/address */
static int iface_mac(const char *root, const char *dev, uint8_t out[APMON_ID_LEN])
{
	char path[256];
	char text[32];

	if (dev == NULL || dev[0] == '\0' || strchr(dev, '/') != NULL) {
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

/* 1a. device tree label-mac-device: mac-address, else local-mac-address */
static int dt_label_mac(const char *root, uint8_t out[APMON_ID_LEN])
{
	static const char *const props[] = { "mac-address", "local-mac-address" };
	char node[200];
	char path[512];
	size_t i;

	snprintf(path, sizeof(path), "%s/proc/device-tree/aliases/label-mac-device", root);
	if (read_text(path, node, sizeof(node)) != 0) {
		return -1;
	}
	if (node[0] == '\0') {
		return -1;
	}
	for (i = 0; i < sizeof(props) / sizeof(props[0]); i++) {
		FILE *f;
		size_t n;

		snprintf(path, sizeof(path), "%s/proc/device-tree%s/%s", root, node, props[i]);
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

/* 1b. "label_macaddr": "xx:xx:xx:xx:xx:xx" in board.json (only ever under "system") */
static int board_label_mac(const char *root, uint8_t out[APMON_ID_LEN])
{
	char path[256];
	char *buf;
	char *p;
	char *q;
	char mac[18];
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
				memcpy(mac, p, 17);
				mac[17] = '\0';
				if (apmon_mac_parse(mac, out) == 0 && !mac_is_zero(out)) {
					ret = 0;
				}
			}
		}
	}
	free(buf);
	return ret;
}

/* 4. lowest ifindex with type 1 (ARPHRD_ETHER), as "ip -o link show type ether | head -n1" */
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
		if (iface_mac(root, e->d_name, mac) != 0) {
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

int apmon_factory_mac(const char *root, const char *wan_device, const char *fallback_device,
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
	if (iface_mac(root, wan_device, out) == 0) {
		snprintf(source, source_len, "network.wan.device %s", wan_device);
		return 0;
	}
	for (i = 0; i < sizeof(common) / sizeof(common[0]); i++) {
		if (iface_mac(root, common[i], out) == 0) {
			snprintf(source, source_len, "fallback interface %s", common[i]);
			return 0;
		}
	}
	if (first_ether_mac(root, out, name, sizeof(name)) == 0) {
		snprintf(source, source_len, "first ethernet interface %s", name);
		return 0;
	}
	if (iface_mac(root, fallback_device, out) == 0) {
		snprintf(source, source_len, "device %s", fallback_device);
		return 0;
	}
	snprintf(source, source_len, "none");
	return -1;
}
