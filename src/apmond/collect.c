/*
 * apmond data collection: node status, radios and Wi-Fi clients (ubus iwinfo), wired clients (bridge fdb)
 * Builds the REPORT plaintext described in docs/PROTOCOL.md section 6.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <libubox/blobmsg_json.h>

#include "apmond.h"

#define MAX_WIFI_MACS 512

/* ---------- small helpers ---------- */

static int read_line(const char *path, char *out, size_t out_len)
{
	FILE *f = fopen(path, "r");
	size_t n;

	if (f == NULL) {
		return -1;
	}
	if (fgets(out, (int)out_len, f) == NULL) {
		fclose(f);
		return -1;
	}
	fclose(f);

	n = strlen(out);
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) {
		out[n - 1] = '\0';
		n--;
	}
	return 0;
}

int apmond_read_mac(const char *ifname, uint8_t id[APMON_ID_LEN])
{
	char path[128];
	char line[32];

	snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
	if (read_line(path, line, sizeof(line)) != 0) {
		return -1;
	}
	return apmon_mac_parse(line, id);
}

/* Default IPv4 route from /proc/net/route: outgoing interface and gateway */
int apmond_default_route(char *ifname, size_t ifname_len, char *gateway, size_t gw_len)
{
	FILE *f = fopen("/proc/net/route", "r");
	char line[256];
	int found = -1;

	if (f == NULL) {
		return -1;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char iface[IFNAMSIZ];
		unsigned int dest;
		unsigned int gw;
		unsigned int flags;
		struct in_addr addr;

		if (sscanf(line, "%15s %x %x %x", iface, &dest, &gw, &flags) != 4) {
			continue;
		}
		if (dest != 0 || (flags & 0x2) == 0) {
			continue;
		}

		addr.s_addr = gw;
		snprintf(ifname, ifname_len, "%s", iface);
		inet_ntop(AF_INET, &addr, gateway, (socklen_t)gw_len);
		found = 0;
		break;
	}

	fclose(f);
	return found;
}

/* ---------- synchronous ubus call ---------- */

static void ubus_result_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **out = req->priv;

	(void)type;
	if (msg != NULL) {
		*out = blob_memdup(msg);
	}
}

int apmond_ubus_call(struct ubus_context *ctx, const char *object, const char *method,
		     struct blob_attr *msg, struct blob_attr **out)
{
	uint32_t id;

	*out = NULL;
	if (ctx == NULL) {
		return -1;
	}
	if (ubus_lookup_id(ctx, object, &id) != 0) {
		return -1;
	}
	if (ubus_invoke(ctx, id, method, msg, ubus_result_cb, out, 3000) != 0) {
		free(*out);
		*out = NULL;
		return -1;
	}
	if (*out == NULL) {
		return -1;
	}
	return 0;
}

static struct blob_attr *find_attr(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur;
	size_t rem;

	if (table == NULL) {
		return NULL;
	}
	blob_for_each_attr(cur, table, rem) {
		if (strcmp(blobmsg_name(cur), name) == 0) {
			return cur;
		}
	}
	return NULL;
}

static struct blob_attr *find_in_table(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur;
	size_t rem;

	if (table == NULL) {
		return NULL;
	}
	blobmsg_for_each_attr(cur, table, rem) {
		if (strcmp(blobmsg_name(cur), name) == 0) {
			return cur;
		}
	}
	return NULL;
}

static int attr_int(struct blob_attr *a, int64_t *out)
{
	if (a == NULL) {
		return -1;
	}
	switch (blobmsg_type(a)) {
	case BLOBMSG_TYPE_INT8:
		*out = blobmsg_get_u8(a);
		return 0;
	case BLOBMSG_TYPE_INT16:
		*out = (int16_t)blobmsg_get_u16(a);
		return 0;
	case BLOBMSG_TYPE_INT32:
		*out = (int32_t)blobmsg_get_u32(a);
		return 0;
	case BLOBMSG_TYPE_INT64:
		*out = (int64_t)blobmsg_get_u64(a);
		return 0;
	case BLOBMSG_TYPE_DOUBLE:
		*out = (int64_t)blobmsg_get_double(a);
		return 0;
	default:
		return -1;
	}
}

static void json_int_attr(struct apmon_json *j, const char *key, struct blob_attr *a)
{
	int64_t v;

	if (attr_int(a, &v) == 0) {
		apmon_json_int(j, key, v);
	} else {
		apmon_json_null(j, key);
	}
}

static void json_string_attr(struct apmon_json *j, const char *key, struct blob_attr *a)
{
	if (a != NULL && blobmsg_type(a) == BLOBMSG_TYPE_STRING) {
		apmon_json_string(j, key, blobmsg_get_string(a));
	} else {
		apmon_json_null(j, key);
	}
}

/* ---------- node ---------- */

static void add_addresses(struct apmon_json *j, const char *device)
{
	struct ifaddrs *list = NULL;
	struct ifaddrs *ifa;
	char ula[INET6_ADDRSTRLEN] = "";

	if (getifaddrs(&list) != 0) {
		apmon_json_null(j, "node_ula");
		return;
	}

	apmon_json_open_array(j, "ipv4_addresses");
	for (ifa = list; ifa != NULL; ifa = ifa->ifa_next) {
		char addr[INET_ADDRSTRLEN];
		char entry[32];
		int prefix = 0;
		uint32_t mask;

		if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, device) != 0) {
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6 && ula[0] == '\0') {
			struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ifa->ifa_addr;

			if ((a6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
				inet_ntop(AF_INET6, &a6->sin6_addr, ula, sizeof(ula));
			}
			continue;
		}
		if (ifa->ifa_addr->sa_family != AF_INET) {
			continue;
		}

		inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, addr, sizeof(addr));
		if (ifa->ifa_netmask != NULL) {
			mask = ntohl(((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr);
			while (mask & 0x80000000u) {
				prefix++;
				mask <<= 1;
			}
		}
		snprintf(entry, sizeof(entry), "%s/%d", addr, prefix);
		apmon_json_string(j, NULL, entry);
	}
	apmon_json_close_array(j);

	if (ula[0] != '\0') {
		apmon_json_string(j, "node_ula", ula);
	} else {
		apmon_json_null(j, "node_ula");
	}

	freeifaddrs(list);
}

static void add_node(struct apmond *a, struct apmon_json *j)
{
	struct sysinfo si;
	struct statvfs vfs;
	char host[65] = "";
	char line[128];
	char release[64] = "";
	FILE *f;

	apmon_json_open_object(j, "node");
	apmon_json_string(j, "id", a->id_str);

	gethostname(host, sizeof(host) - 1);
	apmon_json_string(j, "hostname", host);

	if (read_line("/tmp/sysinfo/model", line, sizeof(line)) == 0) {
		apmon_json_string(j, "model", line);
	} else {
		apmon_json_null(j, "model");
	}

	apmon_json_string(j, "apmond_version", APMOND_VERSION);

	f = fopen("/etc/openwrt_release", "r");
	if (f != NULL) {
		while (fgets(line, sizeof(line), f) != NULL) {
			if (sscanf(line, "DISTRIB_RELEASE='%63[^']'", release) == 1) {
				break;
			}
		}
		fclose(f);
	}
	if (release[0] != '\0') {
		apmon_json_string(j, "openwrt_release", release);
	} else {
		apmon_json_null(j, "openwrt_release");
	}

	if (a->role == ROLE_COLLECTOR) {
		apmon_json_string(j, "role", "collector");
	} else {
		apmon_json_string(j, "role", "peer");
	}

	if (sysinfo(&si) == 0) {
		double scale = 1.0 / (double)(1 << SI_LOAD_SHIFT);

		apmon_json_int(j, "uptime", si.uptime);
		apmon_json_open_array(j, "load");
		apmon_json_double(j, NULL, (double)si.loads[0] * scale);
		apmon_json_double(j, NULL, (double)si.loads[1] * scale);
		apmon_json_double(j, NULL, (double)si.loads[2] * scale);
		apmon_json_close_array(j);
		apmon_json_int(j, "free_ram_kb", (int64_t)si.freeram * si.mem_unit / 1024);
	}

	if (statvfs("/overlay", &vfs) == 0) {
		apmon_json_int(j, "free_flash_kb", (int64_t)vfs.f_bavail * (int64_t)vfs.f_frsize / 1024);
	} else {
		apmon_json_null(j, "free_flash_kb");
	}

	if (read_line("/sys/class/thermal/thermal_zone0/temp", line, sizeof(line)) == 0) {
		apmon_json_int(j, "cpu_temperature_c", atoi(line) / 1000);
	} else {
		apmon_json_null(j, "cpu_temperature_c");
	}

	if (read_line("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", line, sizeof(line)) == 0) {
		apmon_json_int(j, "cpu_frequency_mhz", atoi(line) / 1000);
	} else {
		apmon_json_null(j, "cpu_frequency_mhz");
	}

	add_addresses(j, a->cfg.device);
	apmon_json_bool(j, "default_passphrase", a->cfg.default_seed);
	apmon_json_close_object(j);
}

/* ---------- Wi-Fi: ubus iwinfo (rpcd-mod-iwinfo) ---------- */

struct wifi_macs {
	char mac[MAX_WIFI_MACS][18];
	int count;
	char ifnames[32][IFNAMSIZ];
	int if_count;
};

static struct blob_attr *iwinfo_call(struct apmond *a, const char *method, const char *device)
{
	struct blob_buf b;
	struct blob_attr *out = NULL;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	if (device != NULL) {
		blobmsg_add_string(&b, "device", device);
	}
	apmond_ubus_call(a->ubus, "iwinfo", method, b.head, &out);
	blob_buf_free(&b);
	return out;
}

static void add_wifi_client(struct apmon_json *j, struct blob_attr *sta, const char *ifname, uint64_t now_ms,
			    struct wifi_macs *macs)
{
	struct blob_attr *mac = find_in_table(sta, "mac");
	struct blob_attr *rx = find_in_table(sta, "rx");
	struct blob_attr *tx = find_in_table(sta, "tx");
	int64_t inactive = 0;
	char lower[18];
	int i;

	if (mac == NULL || blobmsg_type(mac) != BLOBMSG_TYPE_STRING) {
		return;
	}

	snprintf(lower, sizeof(lower), "%s", blobmsg_get_string(mac));
	for (i = 0; lower[i] != '\0'; i++) {
		if (lower[i] >= 'A' && lower[i] <= 'F') {
			lower[i] = (char)(lower[i] - 'A' + 'a');
		}
	}

	if (macs->count < MAX_WIFI_MACS) {
		snprintf(macs->mac[macs->count], 18, "%s", lower);
		macs->count++;
	}

	attr_int(find_in_table(sta, "inactive"), &inactive);

	apmon_json_open_object(j, NULL);
	apmon_json_string(j, "mac", lower);
	apmon_json_string(j, "kind", "wifi");
	apmon_json_string(j, "ap", ifname);
	apmon_json_null(j, "vlan");
	json_int_attr(j, "signal_avg_dbm", find_in_table(sta, "signal_avg"));
	json_int_attr(j, "signal_dbm", find_in_table(sta, "signal"));
	json_int_attr(j, "ack_signal_avg_dbm", find_in_table(sta, "ack_signal_avg"));
	json_int_attr(j, "tx_bitrate_kbps", find_in_table(tx, "rate"));
	json_int_attr(j, "rx_bitrate_kbps", find_in_table(rx, "rate"));
	json_int_attr(j, "tx_bytes", find_in_table(tx, "bytes"));
	json_int_attr(j, "rx_bytes", find_in_table(rx, "bytes"));
	json_int_attr(j, "tx_retries", find_in_table(tx, "retries"));
	json_int_attr(j, "connected_ms", find_in_table(sta, "connected_time"));
	apmon_json_int(j, "inactive_ms", inactive);
	apmon_json_int(j, "last_seen", (int64_t)now_ms - inactive);
	apmon_json_close_object(j);
}

/* Writes "radios" and returns the Wi-Fi clients JSON fragments into clients_json */
static void add_wifi(struct apmond *a, struct apmon_json *j, struct apmon_json *clients, uint64_t now_ms,
		     struct wifi_macs *macs)
{
	struct blob_attr *devices = iwinfo_call(a, "devices", NULL);
	struct blob_attr *list;
	struct blob_attr *dev;
	size_t rem;

	apmon_json_open_array(j, "radios");

	list = find_attr(devices, "devices");
	if (list == NULL) {
		apmon_json_close_array(j);
		free(devices);
		return;
	}

	blobmsg_for_each_attr(dev, list, rem) {
		const char *ifname;
		struct blob_attr *info;
		struct blob_attr *mode;
		struct blob_attr *assoc;
		struct blob_attr *results;
		struct blob_attr *sta;
		size_t srem;

		if (blobmsg_type(dev) != BLOBMSG_TYPE_STRING) {
			continue;
		}
		ifname = blobmsg_get_string(dev);

		info = iwinfo_call(a, "info", ifname);
		mode = find_attr(info, "mode");
		if (mode == NULL || strcmp(blobmsg_get_string(mode), "Master") != 0) {
			free(info);
			continue;
		}

		if (macs->if_count < 32) {
			snprintf(macs->ifnames[macs->if_count], IFNAMSIZ, "%s", ifname);
			macs->if_count++;
		}

		/* One entry per AP interface (first cut: radios are not yet grouped by phy) */
		apmon_json_open_object(j, NULL);
		json_string_attr(j, "phy", find_attr(info, "phy"));
		json_int_attr(j, "channel", find_attr(info, "channel"));
		json_int_attr(j, "frequency_mhz", find_attr(info, "frequency"));
		json_string_attr(j, "htmode", find_attr(info, "htmode"));
		json_int_attr(j, "txpower_dbm", find_attr(info, "txpower"));
		apmon_json_open_array(j, "aps");
		apmon_json_open_object(j, NULL);
		apmon_json_string(j, "ifname", ifname);
		json_string_attr(j, "ssid", find_attr(info, "ssid"));
		json_string_attr(j, "bssid", find_attr(info, "bssid"));
		apmon_json_null(j, "vlan");
		apmon_json_close_object(j);
		apmon_json_close_array(j);
		apmon_json_close_object(j);

		assoc = iwinfo_call(a, "assoclist", ifname);
		results = find_attr(assoc, "results");
		if (results != NULL) {
			blobmsg_for_each_attr(sta, results, srem) {
				add_wifi_client(clients, sta, ifname, now_ms, macs);
			}
		}

		free(assoc);
		free(info);
	}

	apmon_json_close_array(j);
	free(devices);
}

/* ---------- wired clients: bridge forwarding database ---------- */

struct fdb_entry {
	uint8_t mac[6];
	uint8_t port_no;
	uint8_t is_local;
	uint32_t ageing_timer_value;   /* clock_t, centiseconds */
	uint8_t port_hi;
	uint8_t pad0;
	uint16_t unused;
};

static int port_name(const char *bridge, unsigned int port, char *out, size_t out_len)
{
	char path[512];
	char line[32];
	struct dirent *de;
	DIR *d;
	int found = -1;

	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", bridge);
	d = opendir(path);
	if (d == NULL) {
		return -1;
	}

	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.') {
			continue;
		}
		snprintf(path, sizeof(path), "/sys/class/net/%s/brif/%s/port_no", bridge, de->d_name);
		if (read_line(path, line, sizeof(line)) != 0) {
			continue;
		}
		if ((unsigned int)strtoul(line, NULL, 0) == port && strlen(de->d_name) < out_len) {
			memcpy(out, de->d_name, strlen(de->d_name) + 1);
			found = 0;
			break;
		}
	}

	closedir(d);
	return found;
}

static int is_wifi_mac_or_if(struct wifi_macs *macs, const char *mac, const char *port)
{
	int i;

	for (i = 0; i < macs->count; i++) {
		if (strcmp(macs->mac[i], mac) == 0) {
			return 1;
		}
	}
	for (i = 0; i < macs->if_count; i++) {
		if (strcmp(macs->ifnames[i], port) == 0) {
			return 1;
		}
	}
	return 0;
}

static void add_wired(struct apmond *a, struct apmon_json *clients, uint64_t now_ms, struct wifi_macs *macs)
{
	char bridge[32];
	char path[128];
	char *dot;
	struct fdb_entry e;
	FILE *f;

	/* br-lan.10 (VLAN subinterface on a vlan_filtering bridge) -> br-lan */
	snprintf(bridge, sizeof(bridge), "%s", a->cfg.device);
	dot = strchr(bridge, '.');
	if (dot != NULL) {
		*dot = '\0';
	}

	snprintf(path, sizeof(path), "/sys/class/net/%s/brforward", bridge);
	f = fopen(path, "rb");
	if (f == NULL) {
		return;
	}

	while (fread(&e, sizeof(e), 1, f) == 1) {
		uint8_t id[APMON_ID_LEN];
		char mac[18];
		char port[IFNAMSIZ] = "";
		char speed_path[128];
		char speed[16];
		unsigned int port_no = ((unsigned int)e.port_hi << 8) | e.port_no;
		int64_t age_ms = (int64_t)e.ageing_timer_value * 10;

		if (e.is_local) {
			continue;
		}

		memcpy(id, e.mac, APMON_ID_LEN);
		apmon_mac_format(id, mac);
		port_name(bridge, port_no, port, sizeof(port));

		if (is_wifi_mac_or_if(macs, mac, port)) {
			continue;
		}

		apmon_json_open_object(clients, NULL);
		apmon_json_string(clients, "mac", mac);
		apmon_json_string(clients, "kind", "wired");
		apmon_json_string(clients, "bridge", bridge);
		apmon_json_string(clients, "port", port);
		apmon_json_null(clients, "vlan");

		snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", port);
		if (port[0] != '\0' && read_line(speed_path, speed, sizeof(speed)) == 0 && atoi(speed) > 0) {
			apmon_json_int(clients, "speed_mbps", atoi(speed));
		} else {
			apmon_json_null(clients, "speed_mbps");
		}

		apmon_json_int(clients, "last_seen", (int64_t)now_ms - age_ms);
		apmon_json_close_object(clients);
	}

	fclose(f);
}

/* ---------- report ---------- */

char *apmond_build_report(struct apmond *a, uint64_t now_ms)
{
	struct apmon_json j;
	struct apmon_json clients;
	struct wifi_macs *macs = calloc(1, sizeof(*macs));
	if (macs == NULL) {
		return NULL;
	}

	apmon_json_init(&j);
	apmon_json_init(&clients);

	apmon_json_open_object(&j, NULL);
	apmon_json_int(&j, "v", 2);
	apmon_json_string(&j, "type", "report");
	apmon_json_int(&j, "report_time", (int64_t)now_ms);
	apmon_json_int(&j, "interval", a->cfg.interval);
	add_node(a, &j);

	/* clients are written into their own buffer, then spliced in as an array */
	apmon_json_open_array(&clients, NULL);
	add_wifi(a, &j, &clients, now_ms, macs);
	add_wired(a, &clients, now_ms, macs);
	apmon_json_close_array(&clients);

	if (clients.failed) {
		j.failed = 1;
	} else {
		apmon_json_raw(&j, "clients", clients.buf);
	}

	apmon_json_open_object(&j, "blocks");
	apmon_json_close_object(&j);
	apmon_json_close_object(&j);

	apmon_json_free(&clients);
	free(macs);

	if (j.failed) {
		apmon_json_free(&j);
		return NULL;
	}
	return j.buf;
}
