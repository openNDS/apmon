/*
 * apmond data collection: node status, radios and Wi-Fi clients (nl80211), wired clients (bridge fdb)
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

#include <linux/nl80211.h>
#include <libubox/blobmsg_json.h>
#include <uci.h>

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

/* ---------- Wi-Fi: nl80211 (nl80211.c) and uci wireless ---------- */

#define MAX_WIFI_IFACES 32
#define MAX_STATIONS 256

struct wifi_macs {
	char mac[MAX_WIFI_MACS][18];
	int count;
	char ifnames[32][IFNAMSIZ];
	int if_count;
};

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

static void json_flag_int(struct apmon_json *j, const char *key, unsigned int have, unsigned int flag, int64_t v)
{
	if (have & flag) {
		apmon_json_int(j, key, v);
	} else {
		apmon_json_null(j, key);
	}
}

/* What uci wireless says about one interface (matched by option ifname, which netifd and mesh11sd set) */
struct uci_wifi {
	int found;
	char encryption[32];
	char mesh_id[64];
	char htmode[16];
	char ssid[33];
};

static void uci_wifi_lookup(struct uci_context *ctx, struct uci_package *pkg, const char *ifname, struct uci_wifi *out)
{
	struct uci_element *e;

	memset(out, 0, sizeof(*out));
	if (ctx == NULL || pkg == NULL) {
		return;
	}
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *iface = uci_to_section(e);
		struct uci_section *radio = NULL;
		const char *v;

		if (strcmp(iface->type, "wifi-iface") != 0) {
			continue;
		}
		v = uci_lookup_option_string(ctx, iface, "ifname");
		if (v == NULL || strcmp(v, ifname) != 0) {
			continue;
		}
		out->found = 1;
		v = uci_lookup_option_string(ctx, iface, "encryption");
		if (v != NULL) {
			snprintf(out->encryption, sizeof(out->encryption), "%s", v);
		}
		v = uci_lookup_option_string(ctx, iface, "ssid");
		if (v != NULL) {
			snprintf(out->ssid, sizeof(out->ssid), "%s", v);
		}
		v = uci_lookup_option_string(ctx, iface, "mesh_id");
		if (v != NULL) {
			snprintf(out->mesh_id, sizeof(out->mesh_id), "%s", v);
		}
		v = uci_lookup_option_string(ctx, iface, "device");
		if (v != NULL) {
			radio = uci_lookup_section(ctx, pkg, v);
		}
		if (radio != NULL) {
			v = uci_lookup_option_string(ctx, radio, "htmode");
			if (v != NULL) {
				snprintf(out->htmode, sizeof(out->htmode), "%s", v);
			}
		}
		return;
	}
}

/* "encryption": the uci value (psk2, sae, sae-mixed, ...), "none" when unset, null if not in uci */
static void json_encryption(struct apmon_json *j, const struct uci_wifi *u)
{
	if (!u->found) {
		apmon_json_null(j, "encryption");
	} else if (u->encryption[0] == '\0') {
		apmon_json_string(j, "encryption", "none");
	} else {
		apmon_json_string(j, "encryption", u->encryption);
	}
}

/* phy name (phy0, or what the board renamed it to) from sysfs, else phy<wiphy index> */
static void phy_name(const struct apmon_wifi_iface *ifc, char *out, size_t len)
{
	char path[96];

	snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211/name", ifc->ifname);
	if (read_line(path, out, len) == 0 && out[0] != '\0') {
		return;
	}
	snprintf(out, len, "phy%d", ifc->wiphy);
}

static const int *wiphy_families(const struct apmond_wiphy_caps *caps, int wiphy)
{
	int i;

	for (i = 0; i < caps->count; i++) {
		if (caps->wiphy[i] == wiphy) {
			return caps->family[i];
		}
	}
	return NULL;
}

static int is_reported(const struct apmon_wifi_iface *ifc)
{
	if (ifc->iftype == NL80211_IFTYPE_AP || ifc->iftype == NL80211_IFTYPE_MESH_POINT) {
		return 1;
	}
	return 0;
}

static void add_wifi_client(struct apmon_json *j, const struct apmon_wifi_sta *sta, const struct apmon_wifi_iface *ap,
			    uint64_t now_ms, struct wifi_macs *macs)
{
	char mac[18];
	char bssid[18];

	apmon_mac_format(sta->mac, mac);
	if (macs->count < MAX_WIFI_MACS) {
		snprintf(macs->mac[macs->count], 18, "%s", mac);
		macs->count++;
	}

	apmon_json_open_object(j, NULL);
	apmon_json_string(j, "client_mac", mac);
	apmon_json_string(j, "kind", "wifi");
	if (ap->have_ssid) {
		apmon_json_string(j, "ap_ssid", ap->ssid);
	} else {
		apmon_json_null(j, "ap_ssid");
	}
	apmon_json_string(j, "ap_ifname", ap->ifname);
	if (ap->have_mac) {
		apmon_mac_format(ap->mac, bssid);
		apmon_json_string(j, "ap_bssid", bssid);
	} else {
		apmon_json_null(j, "ap_bssid");
	}
	json_vlan(j, apmond_port_vlan(ap->ifname, now_ms));
	json_vxlan(j, ap->ifname, now_ms);
	json_flag_int(j, "signal_avg_dbm", sta->have, APMON_STA_SIGNAL_AVG, sta->signal_avg);
	json_flag_int(j, "signal_dbm", sta->have, APMON_STA_SIGNAL, sta->signal);
	json_flag_int(j, "ack_signal_avg_dbm", sta->have, APMON_STA_ACK_SIGNAL_AVG, sta->ack_signal_avg);
	json_flag_int(j, "tx_bitrate_kbps", sta->have, APMON_STA_TX_RATE, sta->tx_rate_kbps);
	json_flag_int(j, "rx_bitrate_kbps", sta->have, APMON_STA_RX_RATE, sta->rx_rate_kbps);
	json_flag_int(j, "tx_bytes", sta->have, APMON_STA_TX_BYTES, (int64_t)sta->tx_bytes);
	json_flag_int(j, "rx_bytes", sta->have, APMON_STA_RX_BYTES, (int64_t)sta->rx_bytes);
	json_flag_int(j, "tx_retries", sta->have, APMON_STA_TX_RETRIES, sta->tx_retries);
	json_flag_int(j, "connected_s", sta->have, APMON_STA_CONNECTED, sta->connected_s);
	apmon_json_int(j, "inactive_ms", sta->inactive_ms);
	apmon_json_int(j, "last_seen", (int64_t)now_ms - sta->inactive_ms);
	apmon_json_close_object(j);
}

/*
 * Radio fields of the phy of ifs[first]: channel, frequency and txpower from the first
 * interface of the phy with a frequency; htmode = family + width, the family from the uci
 * htmode prefix (what the radio is configured for), else the wiphy capabilities for the band,
 * the width the widest any interface of the phy runs. uci htmode as is if nl80211 has no width.
 */
static void write_radio_fields(struct apmon_json *j, const struct apmon_wifi_iface *ifs, const int *rep, int count,
			       int first, const char *phy, const char *const *phys, const struct uci_wifi *uw,
			       const struct apmond_wiphy_caps *caps)
{
	int src = -1;
	int width = -1;
	int family = -1;
	const char *uci_htmode = "";
	const int *fams;
	char htmode[16];
	int k;

	for (k = first; k < count; k++) {
		if (!rep[k] || strcmp(phys[k], phy) != 0) {
			continue;
		}
		if (src < 0 && ifs[k].freq > 0) {
			src = k;
		}
		width = apmon_wider_width(width, ifs[k].width);
		if (uci_htmode[0] == '\0' && uw[k].htmode[0] != '\0') {
			uci_htmode = uw[k].htmode;
		}
	}

	family = apmon_htmode_family(uci_htmode);
	fams = wiphy_families(caps, ifs[first].wiphy);
	if (family < 0 && src >= 0 && fams != NULL) {
		int band = apmon_freq_band(ifs[src].freq);

		if (band >= 0 && band < APMON_BANDS) {
			family = fams[band];
		}
	}

	if (src >= 0) {
		apmon_json_int(j, "channel", apmon_freq_to_channel(ifs[src].freq));
		apmon_json_int(j, "frequency_mhz", ifs[src].freq);
	} else {
		apmon_json_null(j, "channel");
		apmon_json_null(j, "frequency_mhz");
	}
	if (apmon_htmode_string(family, width, htmode, sizeof(htmode)) == 0) {
		apmon_json_string(j, "htmode", htmode);
	} else if (uci_htmode[0] != '\0') {
		apmon_json_string(j, "htmode", uci_htmode);
	} else {
		apmon_json_null(j, "htmode");
	}
	if (src >= 0 && ifs[src].have_txpower) {
		apmon_json_int(j, "txpower_dbm", ifs[src].txpower_mbm / 100);
	} else {
		apmon_json_null(j, "txpower_dbm");
	}
}

struct wifi_state {
	struct apmon_wifi_iface ifs[MAX_WIFI_IFACES];
	struct uci_wifi uw[MAX_WIFI_IFACES];
	char phys[MAX_WIFI_IFACES][IFNAMSIZ];
	const char *phyp[MAX_WIFI_IFACES];
	int rep[MAX_WIFI_IFACES];
	struct apmond_wiphy_caps caps;
	struct apmon_wifi_sta stas[MAX_STATIONS];
};

static struct blob_attr *blob_child(struct blob_attr *table, const char *name)
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

static void copy_child_string(struct blob_attr *table, const char *name, char *out, size_t len)
{
	struct blob_attr *a = blob_child(table, name);

	if (a != NULL && blobmsg_type(a) == BLOBMSG_TYPE_STRING) {
		snprintf(out, len, "%s", blobmsg_get_string(a));
	}
}

/*
 * netifd's live view (ubus network.wireless status): the config it applied, including
 * changes mesh11sd and others keep uncommitted in /tmp/.uci, which the jailed daemon cannot
 * read. Fills the uci_wifi of every interface it knows; the rest keep the /etc/config lookup.
 */
static void netifd_wifi_lookup(struct apmond *a, struct wifi_state *w, int count)
{
	struct blob_buf b;
	struct blob_attr *status = NULL;
	struct blob_attr *radio;
	size_t rem;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	apmond_ubus_call(a->ubus, "network.wireless", "status", b.head, &status);
	blob_buf_free(&b);
	if (status == NULL) {
		return;
	}
	blob_for_each_attr(radio, status, rem) {
		struct blob_attr *rconf = blob_child(radio, "config");
		struct blob_attr *ifaces = blob_child(radio, "interfaces");
		struct blob_attr *ifc;
		size_t irem;
		char htmode[16] = "";

		if (ifaces == NULL) {
			continue;
		}
		copy_child_string(rconf, "htmode", htmode, sizeof(htmode));
		blobmsg_for_each_attr(ifc, ifaces, irem) {
			struct blob_attr *conf = blob_child(ifc, "config");
			char ifname[IFNAMSIZ] = "";
			int i;

			copy_child_string(ifc, "ifname", ifname, sizeof(ifname));
			if (ifname[0] == '\0') {
				copy_child_string(conf, "ifname", ifname, sizeof(ifname));
			}
			for (i = 0; i < count; i++) {
				struct uci_wifi *u = &w->uw[i];

				if (strcmp(w->ifs[i].ifname, ifname) != 0) {
					continue;
				}
				memset(u, 0, sizeof(*u));
				u->found = 1;
				copy_child_string(conf, "encryption", u->encryption, sizeof(u->encryption));
				copy_child_string(conf, "mesh_id", u->mesh_id, sizeof(u->mesh_id));
				copy_child_string(conf, "ssid", u->ssid, sizeof(u->ssid));
				snprintf(u->htmode, sizeof(u->htmode), "%s", htmode);
			}
		}
	}
	free(status);
}

static struct blob_attr *blob_child_top(struct blob_attr *msg, const char *name)
{
	struct blob_attr *cur;
	size_t rem;

	if (msg == NULL) {
		return NULL;
	}
	blob_for_each_attr(cur, msg, rem) {
		if (strcmp(blobmsg_name(cur), name) == 0) {
			return cur;
		}
	}
	return NULL;
}

/*
 * IPv4 address of the lan's upstream router as netifd knows it (ubus network.interface.lan):
 * the DHCP server, else the nexthop of its default route. On a mesh peer the kernel default
 * route can be on another device (mesh11sd's br-tun69); the collector is on the lan.
 */
int apmond_lan_gateway(struct ubus_context *ctx, char *out, size_t len)
{
	struct blob_buf b;
	struct blob_attr *status = NULL;
	struct blob_attr *routes;
	struct blob_attr *r;
	size_t rem;
	int ret = -1;

	out[0] = '\0';
	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	apmond_ubus_call(ctx, "network.interface.lan", "status", b.head, &status);
	blob_buf_free(&b);
	if (status == NULL) {
		return -1;
	}
	copy_child_string(blob_child_top(status, "data"), "dhcpserver", out, len);
	if (out[0] != '\0') {
		ret = 0;
	}
	routes = blob_child_top(status, "route");
	if (ret != 0 && routes != NULL) {
		blobmsg_for_each_attr(r, routes, rem) {
			char target[48] = "";

			copy_child_string(r, "target", target, sizeof(target));
			if (strcmp(target, "0.0.0.0") != 0) {
				continue;
			}
			copy_child_string(r, "nexthop", out, len);
			if (out[0] != '\0' && strcmp(out, "0.0.0.0") != 0) {
				ret = 0;
				break;
			}
		}
	}
	free(status);
	return ret;
}

static void write_iface(struct apmon_json *j, struct wifi_state *w, int k, uint64_t now_ms)
{
	const struct apmon_wifi_iface *ifc = &w->ifs[k];
	char bssid[18];

	apmon_json_open_object(j, NULL);
	apmon_json_string(j, "ifname", ifc->ifname);
	if (ifc->iftype == NL80211_IFTYPE_MESH_POINT) {
		if (w->uw[k].mesh_id[0] != '\0') {
			apmon_json_string(j, "mesh_id", w->uw[k].mesh_id);
		} else {
			apmon_json_null(j, "mesh_id");
		}
	} else if (ifc->have_ssid) {
		apmon_json_string(j, "ssid", ifc->ssid);
	} else if (w->uw[k].ssid[0] != '\0') {
		apmon_json_string(j, "ssid", w->uw[k].ssid);
	} else {
		apmon_json_null(j, "ssid");
	}
	if (ifc->have_mac) {
		apmon_mac_format(ifc->mac, bssid);
		apmon_json_string(j, "bssid", bssid);
	} else {
		apmon_json_null(j, "bssid");
	}
	json_encryption(j, &w->uw[k]);
	json_vlan(j, apmond_port_vlan(ifc->ifname, now_ms));
	json_vxlan(j, ifc->ifname, now_ms);
	apmon_json_close_object(j);
}

/*
 * One "radios" entry per phy, with its AP interfaces under "aps" and mesh points under "mesh";
 * stations of the APs go to the clients writer (mesh peers are nodes, not clients).
 */
static void add_wifi(struct apmond *a, struct apmon_json *j, struct apmon_json *clients, uint64_t now_ms,
		     struct wifi_macs *macs)
{
	struct wifi_state *w = calloc(1, sizeof(*w));
	struct uci_context *ctx;
	struct uci_package *pkg = NULL;
	int count = 0;
	int i;
	int k;

	apmon_json_open_array(j, "radios");
	if (w == NULL) {
		apmon_json_close_array(j);
		return;
	}
	apmond_nl80211_snapshot(w->ifs, MAX_WIFI_IFACES, &count, &w->caps);

	ctx = uci_alloc_context();
	if (ctx != NULL && (uci_load(ctx, "wireless", &pkg) != UCI_OK)) {
		pkg = NULL;
	}
	for (i = 0; i < count; i++) {
		w->rep[i] = is_reported(&w->ifs[i]);
		phy_name(&w->ifs[i], w->phys[i], sizeof(w->phys[i]));
		w->phyp[i] = w->phys[i];
		if (w->rep[i]) {
			uci_wifi_lookup(ctx, pkg, w->ifs[i].ifname, &w->uw[i]);
		}
	}
	if (pkg != NULL) {
		uci_unload(ctx, pkg);
	}
	if (ctx != NULL) {
		uci_free_context(ctx);
	}
	netifd_wifi_lookup(a, w, count);

	for (i = 0; i < count; i++) {
		int first_of_phy = 1;

		if (!w->rep[i]) {
			continue;
		}
		for (k = 0; k < i; k++) {
			if (w->rep[k] && strcmp(w->phys[k], w->phys[i]) == 0) {
				first_of_phy = 0;
			}
		}
		if (!first_of_phy) {
			continue;
		}

		apmon_json_open_object(j, NULL);
		apmon_json_string(j, "phy", w->phys[i]);
		write_radio_fields(j, w->ifs, w->rep, count, i, w->phys[i], w->phyp, w->uw, &w->caps);
		apmon_json_open_array(j, "aps");
		for (k = i; k < count; k++) {
			if (w->ifs[k].iftype == NL80211_IFTYPE_AP && strcmp(w->phys[k], w->phys[i]) == 0) {
				write_iface(j, w, k, now_ms);
			}
		}
		apmon_json_close_array(j);
		apmon_json_open_array(j, "mesh");
		for (k = i; k < count; k++) {
			if (w->ifs[k].iftype == NL80211_IFTYPE_MESH_POINT && strcmp(w->phys[k], w->phys[i]) == 0) {
				write_iface(j, w, k, now_ms);
			}
		}
		apmon_json_close_array(j);
		apmon_json_close_object(j);
	}

	for (i = 0; i < count; i++) {
		int n;

		if (w->ifs[i].iftype != NL80211_IFTYPE_AP) {
			continue;
		}
		if (macs->if_count < 32) {
			snprintf(macs->ifnames[macs->if_count], IFNAMSIZ, "%s", w->ifs[i].ifname);
			macs->if_count++;
		}
		n = apmond_nl80211_stations(w->ifs[i].ifindex, w->stas, MAX_STATIONS);
		for (k = 0; k < n; k++) {
			add_wifi_client(clients, &w->stas[k], &w->ifs[i], now_ms, macs);
		}
	}

	apmon_json_close_array(j);
	free(w);
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
		 * They are remote, Wi-Fi clients come from nl80211 instead */
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
