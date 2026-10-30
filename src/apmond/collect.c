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
#include <sys/stat.h>
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

	if (apmond.node_ula[0] != '\0') {
		apmon_json_string(j, "node_ula", apmond.node_ula);
	} else if (ula[0] != '\0') {
		apmon_json_string(j, "node_ula", ula);
	} else {
		apmon_json_null(j, "node_ula");
	}

	freeifaddrs(list);
}

/* package_version, build_commit, running/installed sha256, restart_needed (null when unknown) */
static void add_identity(struct apmon_json *j)
{
	int restart;

	apmond_identity_refresh();
	apmon_json_string(j, "package_version", APMOND_PACKAGE_VERSION);
	apmon_json_string(j, "build_commit", APMOND_BUILD_COMMIT);
	if (apmond.running_sha256[0] != '\0') {
		apmon_json_string(j, "running_sha256", apmond.running_sha256);
	} else {
		apmon_json_null(j, "running_sha256");
	}
	if (apmond.installed_sha256[0] != '\0') {
		apmon_json_string(j, "installed_sha256", apmond.installed_sha256);
	} else {
		apmon_json_null(j, "installed_sha256");
	}
	restart = apmond_restart_needed();
	if (restart < 0) {
		apmon_json_null(j, "restart_needed");
	} else {
		apmon_json_bool(j, "restart_needed", restart);
	}
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
	add_identity(j);

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

		char load[16];
		int i;

		apmon_json_int(j, "uptime_s", si.uptime);
		/* as 1.x: two decimal strings, so the JSON shows 0.58, not 0.57999999999999996 */
		apmon_json_open_array(j, "load");
		for (i = 0; i < 3; i++) {
			snprintf(load, sizeof(load), "%.2f", (double)si.loads[i] * scale);
			apmon_json_string(j, NULL, load);
		}
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

	add_addresses(j, a->cfg.netdev);
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

/* "vlan": N, or null when the port has no access VLAN */
static void json_vlan(struct apmon_json *j, int vid)
{
	if (vid > 0) {
		apmon_json_int(j, "vlan", vid);
	} else {
		apmon_json_null(j, "vlan");
	}
}

/* "vxlan": {"vni": N, "device": "vxlan0"} when the port is or shares a bridge with a vxlan device, else null */
static void json_vxlan(struct apmon_json *j, const char *port, uint64_t now_ms)
{
	uint32_t vni = 0;
	char device[IFNAMSIZ];

	if (!apmond_port_vxlan(port, now_ms, &vni, device, sizeof(device))) {
		apmon_json_null(j, "vxlan");
		return;
	}
	apmon_json_open_object(j, "vxlan");
	apmon_json_int(j, "vni", (int64_t)vni);
	apmon_json_string(j, "device", device);
	apmon_json_close_object(j);
}

static void add_wifi_client(struct apmon_json *j, struct blob_attr *sta, const char *ifname, struct blob_attr *info,
			    uint64_t now_ms,
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
	apmon_json_string(j, "client_mac", lower);
	apmon_json_string(j, "kind", "wifi");
	json_string_attr(j, "ap_ssid", find_attr(info, "ssid"));
	apmon_json_string(j, "ap_ifname", ifname);
	json_string_attr(j, "ap_bssid", find_attr(info, "bssid"));
	json_vlan(j, apmond_port_vlan(ifname, now_ms));
	json_vxlan(j, ifname, now_ms);
	json_int_attr(j, "signal_avg_dbm", find_in_table(sta, "signal_avg"));
	json_int_attr(j, "signal_dbm", find_in_table(sta, "signal"));
	json_int_attr(j, "ack_signal_avg_dbm", find_in_table(sta, "ack_signal_avg"));
	json_int_attr(j, "tx_bitrate_kbps", find_in_table(tx, "rate"));
	json_int_attr(j, "rx_bitrate_kbps", find_in_table(rx, "rate"));
	json_int_attr(j, "tx_bytes", find_in_table(tx, "bytes"));
	json_int_attr(j, "rx_bytes", find_in_table(rx, "bytes"));
	json_int_attr(j, "tx_retries", find_in_table(tx, "retries"));
	json_int_attr(j, "connected_s", find_in_table(sta, "connected_time"));
	apmon_json_int(j, "inactive_ms", inactive);
	apmon_json_int(j, "last_seen", (int64_t)now_ms - inactive);
	apmon_json_close_object(j);
}

/* Writes "radios" and returns the Wi-Fi clients JSON fragments into clients_json */
#define MAX_APS 16

struct ap_info {
	const char *ifname;
	struct blob_attr *info;
	const char *phy;
};

static const char *info_phy(struct blob_attr *info)
{
	struct blob_attr *phy = find_attr(info, "phy");

	if (phy == NULL || blobmsg_type(phy) != BLOBMSG_TYPE_STRING) {
		return "";
	}
	return blobmsg_get_string(phy);
}

/* One "radios" entry per phy, with its AP interfaces under "aps"; Wi-Fi clients go to the clients writer */
static void add_wifi(struct apmond *a, struct apmon_json *j, struct apmon_json *clients, uint64_t now_ms,
		     struct wifi_macs *macs)
{
	struct blob_attr *devices = iwinfo_call(a, "devices", NULL);
	struct ap_info aps[MAX_APS];
	int count = 0;
	struct blob_attr *list;
	struct blob_attr *dev;
	size_t rem;
	int i;
	int k;

	apmon_json_open_array(j, "radios");

	list = find_attr(devices, "devices");
	if (list != NULL) {
		blobmsg_for_each_attr(dev, list, rem) {
			struct blob_attr *info;
			struct blob_attr *mode;

			if (blobmsg_type(dev) != BLOBMSG_TYPE_STRING || count >= MAX_APS) {
				continue;
			}
			info = iwinfo_call(a, "info", blobmsg_get_string(dev));
			mode = find_attr(info, "mode");
			if (mode == NULL || strcmp(blobmsg_get_string(mode), "Master") != 0) {
				free(info);
				continue;
			}
			aps[count].ifname = blobmsg_get_string(dev);
			aps[count].info = info;
			aps[count].phy = info_phy(info);
			count++;
		}
	}

	for (i = 0; i < count; i++) {
		int first_of_phy = 1;

		for (k = 0; k < i; k++) {
			if (strcmp(aps[k].phy, aps[i].phy) == 0) {
				first_of_phy = 0;
			}
		}
		if (!first_of_phy) {
			continue;
		}

		apmon_json_open_object(j, NULL);
		apmon_json_string(j, "phy", aps[i].phy);
		json_int_attr(j, "channel", find_attr(aps[i].info, "channel"));
		json_int_attr(j, "frequency_mhz", find_attr(aps[i].info, "frequency"));
		json_string_attr(j, "htmode", find_attr(aps[i].info, "htmode"));
		json_int_attr(j, "txpower_dbm", find_attr(aps[i].info, "txpower"));
		apmon_json_open_array(j, "aps");

		for (k = i; k < count; k++) {
			if (strcmp(aps[k].phy, aps[i].phy) != 0) {
				continue;
			}
			apmon_json_open_object(j, NULL);
			apmon_json_string(j, "ifname", aps[k].ifname);
			json_string_attr(j, "ssid", find_attr(aps[k].info, "ssid"));
			json_string_attr(j, "bssid", find_attr(aps[k].info, "bssid"));
			json_vlan(j, apmond_port_vlan(aps[k].ifname, now_ms));
			json_vxlan(j, aps[k].ifname, now_ms);
			apmon_json_close_object(j);
		}

		apmon_json_close_array(j);
		apmon_json_close_object(j);
	}

	for (i = 0; i < count; i++) {
		struct blob_attr *assoc;
		struct blob_attr *results;
		struct blob_attr *sta;
		size_t srem;

		if (macs->if_count < 32) {
			snprintf(macs->ifnames[macs->if_count], IFNAMSIZ, "%s", aps[i].ifname);
			macs->if_count++;
		}

		assoc = iwinfo_call(a, "assoclist", aps[i].ifname);
		results = find_attr(assoc, "results");
		if (results != NULL) {
			blobmsg_for_each_attr(sta, results, srem) {
				add_wifi_client(clients, sta, aps[i].ifname, aps[i].info, now_ms, macs);
			}
		}
		free(assoc);
	}

	for (i = 0; i < count; i++) {
		free(aps[i].info);
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

/* ---------- wired link speed ---------- */

#define SPEED_CACHE_SIZE 8
#define SPEED_CACHE_MS (300 * 1000)

struct speed_cache {
	char ifname[IFNAMSIZ];
	int speed;
	uint64_t at_ms;
};

static struct speed_cache speed_cache[SPEED_CACHE_SIZE];

/* First line of a command's output (popen, so only for the occasional swconfig refresh) */
static int command_output(const char *cmd, char *out, size_t len)
{
	FILE *p = popen(cmd, "r");
	size_t got;

	out[0] = '\0';
	if (p == NULL) {
		return -1;
	}
	got = fread(out, 1, len - 1, p);
	out[got] = '\0';
	pclose(p);
	if (got == 0) {
		return -1;
	}
	return 0;
}

/* VLAN id of a VLAN interface: /proc/net/vlan/<if>, else the .N suffix */
static int vlan_id(const char *ifname)
{
	char path[128];
	char line[256];
	const char *dot;
	FILE *f;
	int vid = -1;

	snprintf(path, sizeof(path), "/proc/net/vlan/%s", ifname);
	f = fopen(path, "r");
	if (f != NULL) {
		while (fgets(line, sizeof(line), f) != NULL) {
			char *v = strstr(line, "VID:");

			if (v != NULL) {
				vid = atoi(v + 4);
				break;
			}
		}
		fclose(f);
	}
	if (vid > 0) {
		return vid;
	}
	dot = strrchr(ifname, '.');
	if (dot != NULL && dot[1] >= '0' && dot[1] <= '9') {
		vid = atoi(dot + 1);
	}
	return vid;
}

/*
 * As apmond 1.x swconfig_vlan_speed: the speed of the untagged switch ports of the VLAN that are up.
 * Several up ports (no MAC to port map without the ARL table): the highest speed.
 */
static int swconfig_vlan_speed(int vid)
{
	static char sw[32];
	char cmd[128];
	char ports[256];
	char *tok;
	char *save = NULL;
	int best = 0;

	if (access("/sbin/swconfig", X_OK) != 0) {
		return 0;
	}
	if (sw[0] == '\0') {
		char list[256];
		char *found;

		snprintf(sw, sizeof(sw), "switch0");
		if (command_output("swconfig list 2>/dev/null", list, sizeof(list)) == 0) {
			found = strstr(list, "Found: ");
			if (found != NULL) {
				sscanf(found + 7, "%31s", sw);
			}
		}
	}

	snprintf(cmd, sizeof(cmd), "swconfig dev %s vlan %d get ports 2>/dev/null", sw, vid);
	if (command_output(cmd, ports, sizeof(ports)) != 0) {
		return 0;
	}

	for (tok = strtok_r(ports, " \n", &save); tok != NULL; tok = strtok_r(NULL, " \n", &save)) {
		char link[256];
		char *s;
		size_t i;
		int tagged = 0;
		int speed;

		for (i = 0; tok[i] != '\0'; i++) {
			if (tok[i] < '0' || tok[i] > '9') {
				tagged = 1;
			}
		}
		if (tagged) {
			continue;
		}
		snprintf(cmd, sizeof(cmd), "swconfig dev %s port %s get link 2>/dev/null", sw, tok);
		if (command_output(cmd, link, sizeof(link)) != 0) {
			continue;
		}
		if (strstr(link, "link:up") == NULL) {
			continue;
		}
		s = strstr(link, "speed:");
		if (s == NULL) {
			continue;
		}
		speed = atoi(s + 6);
		if (speed > best) {
			best = speed;
		}
	}
	return best;
}

/* Mb/s of a wired port, 0 if unknown: sysfs, else swconfig (cached for 5 minutes per interface) */
static int link_speed(const char *ifname, uint64_t now_ms)
{
	char path[128];
	char text[16];
	struct speed_cache *slot = NULL;
	int vid;
	int i;

	if (ifname[0] == '\0') {
		return 0;
	}
	snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
	if (read_line(path, text, sizeof(text)) == 0 && atoi(text) > 0) {
		return atoi(text);
	}

	for (i = 0; i < SPEED_CACHE_SIZE; i++) {
		if (strcmp(speed_cache[i].ifname, ifname) == 0) {
			slot = &speed_cache[i];
			break;
		}
		if (slot == NULL && speed_cache[i].ifname[0] == '\0') {
			slot = &speed_cache[i];
		}
	}
	if (slot == NULL) {
		slot = &speed_cache[0];
	}
	if (strcmp(slot->ifname, ifname) == 0 && now_ms - slot->at_ms < SPEED_CACHE_MS) {
		return slot->speed;
	}

	snprintf(slot->ifname, sizeof(slot->ifname), "%s", ifname);
	slot->at_ms = now_ms;
	slot->speed = 0;
	vid = vlan_id(ifname);
	if (vid > 0) {
		slot->speed = swconfig_vlan_speed(vid);
	}
	return slot->speed;
}

static int is_wireless_port(const char *port)
{
	char path[128];
	struct stat st;

	if (port[0] == '\0') {
		return 0;
	}
	snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", port);
	if (stat(path, &st) == 0) {
		return 1;
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
		int speed;
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

		/* Skip MACs learned over a wireless port (eg an 802.11s mesh backhaul).
		 * They are remote, Wi-Fi clients come from iwinfo instead */
		if (is_wireless_port(port)) {
			continue;
		}

		apmon_json_open_object(clients, NULL);
		apmon_json_string(clients, "client_mac", mac);
		apmon_json_string(clients, "kind", "wired");
		apmon_json_string(clients, "bridge", bridge);
		apmon_json_string(clients, "port", port);
		json_vlan(clients, apmond_port_vlan(port, now_ms));
		json_vxlan(clients, port, now_ms);

		speed = link_speed(port, now_ms);
		if (speed > 0) {
			apmon_json_int(clients, "speed_mbps", speed);
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

	apmond_blocks_json(&j);
	apmon_json_close_object(&j);

	apmon_json_free(&clients);
	free(macs);

	if (j.failed) {
		apmon_json_free(&j);
		return NULL;
	}
	return j.buf;
}
