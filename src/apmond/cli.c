/*
 * apmond command line interface: a thin ubus client of the running daemon.
 * JSON output by default (as "ubus call" prints it), -t / --table for aligned text tables.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg_json.h>

#include "apmond.h"

#define TABLE_BUF (256 * 1024)

static int table_mode;

static void usage(void)
{
	printf("apmond %s - access point monitoring daemon\n"
	       "\n"
	       "Usage: apmond [-t|--table] <command> [arguments]\n"
	       "\n"
	       "  status                       this node: role, ULA, collector, counters, local blocks\n"
	       "  nodes                        collector: all reporting nodes\n"
	       "  clients [node]               collector: all clients, or those of one node\n"
	       "  node <id>                    collector: one node's last report\n"
	       "  block add <name> <json> [ttl] attach a JSON object to this node's reports\n"
	       "  block remove <name>          remove it again\n"
	       "  forget <node|client>         collector: drop a node (with its clients) or a client\n"
	       "  read_log [-f]                print the apmond log; -f keeps following it\n"
	       "  bench                        time the key derivation on this hardware\n"
	       "  run [-c confdir]             run the daemon (used by /etc/init.d/apmond)\n"
	       "  help                         this text\n"
	       "\n"
	       "Output is JSON; -t or --table prints readable tables. Ages: 12s, 5m, 3h, 2d.\n",
	       APMOND_VERSION);
}

/* ---------- ubus ---------- */

struct call_result {
	struct blob_attr *msg;
};

static void call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct call_result *r = req->priv;

	(void)type;
	if (msg != NULL) {
		r->msg = blob_memdup(msg);
	}
}

/* Returns a UBUS_STATUS_* code; *out is the reply (free it) */
static int call(const char *method, struct blob_attr *args, struct blob_attr **out)
{
	struct ubus_context *ctx;
	struct call_result r;
	uint32_t id;
	int ret;

	*out = NULL;
	r.msg = NULL;

	ctx = ubus_connect(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "cannot connect to ubus\n");
		return UBUS_STATUS_CONNECTION_FAILED;
	}
	if (ubus_lookup_id(ctx, "apmond", &id) != 0) {
		fprintf(stderr, "apmond is not running (service apmond start)\n");
		ubus_free(ctx);
		return UBUS_STATUS_NOT_FOUND;
	}

	ret = ubus_invoke(ctx, id, method, args, call_cb, &r, 5000);
	ubus_free(ctx);

	*out = r.msg;
	return ret;
}

static void pretty_attr(struct apmon_pretty *p, struct blob_attr *a, const char *key);

/* The members of a blobmsg table or array */
static void pretty_members(struct apmon_pretty *p, struct blob_attr *a, int is_array)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, a, rem) {
		if (is_array) {
			pretty_attr(p, cur, NULL);
		} else {
			pretty_attr(p, cur, blobmsg_name(cur));
		}
	}
}

static void pretty_attr(struct apmon_pretty *p, struct blob_attr *a, const char *key)
{
	switch (blobmsg_type(a)) {
	case BLOBMSG_TYPE_TABLE:
		apmon_pretty_open_object(p, key);
		pretty_members(p, a, 0);
		apmon_pretty_close(p);
		break;
	case BLOBMSG_TYPE_ARRAY:
		apmon_pretty_open_array(p, key);
		pretty_members(p, a, 1);
		apmon_pretty_close(p);
		break;
	case BLOBMSG_TYPE_STRING:
		apmon_pretty_string(p, key, blobmsg_get_string(a));
		break;
	case BLOBMSG_TYPE_BOOL:
		apmon_pretty_bool(p, key, blobmsg_get_bool(a));
		break;
	case BLOBMSG_TYPE_INT16:
		apmon_pretty_int(p, key, (int16_t)blobmsg_get_u16(a));
		break;
	case BLOBMSG_TYPE_INT32:
		apmon_pretty_int(p, key, (int32_t)blobmsg_get_u32(a));
		break;
	case BLOBMSG_TYPE_INT64:
		apmon_pretty_int(p, key, (long long)(int64_t)blobmsg_get_u64(a));
		break;
	case BLOBMSG_TYPE_DOUBLE:
		apmon_pretty_double(p, key, blobmsg_get_double(a));
		break;
	default:
		apmon_pretty_raw(p, key, "null");
		break;
	}
}

/* JSON as jq and apmond 1.x print it (ubus call keeps libubox's own format) */
static void print_json(struct blob_attr *msg)
{
	struct apmon_pretty p;
	struct blob_attr *cur;
	size_t rem;
	const char *text;

	if (msg == NULL) {
		return;
	}
	apmon_pretty_init(&p);
	apmon_pretty_open_object(&p, NULL);
	blob_for_each_attr(cur, msg, rem) {
		pretty_attr(&p, cur, blobmsg_name(cur));
	}
	apmon_pretty_close(&p);

	text = apmon_pretty_text(&p);
	if (text != NULL) {
		fputs(text, stdout);
	}
	apmon_pretty_free(&p);
}

/* ---------- table helpers ---------- */

static void value_text(struct blob_attr *a, char *out, size_t len)
{
	if (a == NULL) {
		snprintf(out, len, "-");
		return;
	}
	switch (blobmsg_type(a)) {
	case BLOBMSG_TYPE_STRING:
		snprintf(out, len, "%s", blobmsg_get_string(a));
		break;
	case BLOBMSG_TYPE_BOOL:
		if (blobmsg_get_bool(a)) {
			snprintf(out, len, "yes");
		} else {
			snprintf(out, len, "no");
		}
		break;
	case BLOBMSG_TYPE_INT16:
		snprintf(out, len, "%d", (int16_t)blobmsg_get_u16(a));
		break;
	case BLOBMSG_TYPE_INT32:
		snprintf(out, len, "%d", (int32_t)blobmsg_get_u32(a));
		break;
	case BLOBMSG_TYPE_INT64:
		snprintf(out, len, "%lld", (long long)blobmsg_get_u64(a));
		break;
	case BLOBMSG_TYPE_DOUBLE:
		snprintf(out, len, "%.2f", blobmsg_get_double(a));
		break;
	case BLOBMSG_TYPE_TABLE:
		snprintf(out, len, "{...}");
		break;
	case BLOBMSG_TYPE_ARRAY:
		snprintf(out, len, "[...]");
		break;
	default:
		snprintf(out, len, "-");
		break;
	}
}

static struct blob_attr *field(struct blob_attr *table, const char *name)
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

/* The top level of a reply is a blob container, not a blobmsg table */
static struct blob_attr *top_field(struct blob_attr *msg, const char *name)
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

static void add_field(struct apmon_table *t, struct blob_attr *table, const char *name)
{
	char text[128];

	value_text(field(table, name), text, sizeof(text));
	apmon_table_add(t, text);
}

static void add_age(struct apmon_table *t, struct blob_attr *table, const char *name)
{
	struct blob_attr *a = field(table, name);
	char text[16];

	if (a == NULL) {
		apmon_table_add(t, "-");
		return;
	}
	apmon_format_age((int64_t)blobmsg_get_u32(a), text, sizeof(text));
	apmon_table_add(t, text);
}

static void print_table(struct apmon_table *t)
{
	char *buf = malloc(TABLE_BUF);

	if (buf == NULL) {
		return;
	}
	buf[0] = '\0';
	apmon_table_render(t, buf, TABLE_BUF);
	fputs(buf, stdout);
	free(buf);
}

/* KEY VALUE rows, nested tables and arrays flattened as a.b.c */
static void flatten(struct apmon_table *t, struct blob_attr *attr, const char *prefix, int is_array)
{
	struct blob_attr *cur;
	size_t rem;
	int index = 0;

	blobmsg_for_each_attr(cur, attr, rem) {
		char key[160];
		const char *name = blobmsg_name(cur);
		const char *sep = "";
		char text[256];

		if (prefix[0] != '\0') {
			sep = ".";
		}
		if (is_array) {
			snprintf(key, sizeof(key), "%s%s%d", prefix, sep, index);
		} else {
			snprintf(key, sizeof(key), "%s%s%s", prefix, sep, name);
		}
		index++;

		if (blobmsg_type(cur) == BLOBMSG_TYPE_TABLE) {
			flatten(t, cur, key, 0);
			continue;
		}
		if (blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
			flatten(t, cur, key, 1);
			continue;
		}
		value_text(cur, text, sizeof(text));
		apmon_table_add(t, key);
		apmon_table_add(t, text);
	}
}

static void flatten_top(struct apmon_table *t, struct blob_attr *msg, const char *skip)
{
	struct blob_attr *cur;
	size_t rem;

	blob_for_each_attr(cur, msg, rem) {
		const char *name = blobmsg_name(cur);
		char text[256];

		if (skip != NULL && strcmp(name, skip) == 0) {
			continue;
		}
		if (blobmsg_type(cur) == BLOBMSG_TYPE_TABLE) {
			flatten(t, cur, name, 0);
			continue;
		}
		if (blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
			flatten(t, cur, name, 1);
			continue;
		}
		value_text(cur, text, sizeof(text));
		apmon_table_add(t, name);
		apmon_table_add(t, text);
	}
}

/* ---------- commands ---------- */

static int show_key_values(const char *method, struct blob_attr *args, const char *skip)
{
	struct blob_attr *msg;
	struct apmon_table t;
	int ret = call(method, args, &msg);

	if (ret != 0) {
		fprintf(stderr, "%s failed: %s\n", method, ubus_strerror(ret));
		free(msg);
		return 1;
	}
	if (!table_mode) {
		print_json(msg);
		free(msg);
		return 0;
	}
	apmon_table_init(&t, 2);
	apmon_table_add(&t, "KEY");
	apmon_table_add(&t, "VALUE");
	flatten_top(&t, msg, skip);
	print_table(&t);
	apmon_table_free(&t);
	free(msg);
	return 0;
}

static void print_table_indented(struct apmon_table *t, const char *indent)
{
	char *buf = malloc(TABLE_BUF);
	char *line;
	char *next;

	if (buf == NULL) {
		return;
	}
	buf[0] = '\0';
	apmon_table_render(t, buf, TABLE_BUF);
	line = buf;
	while (*line != '\0') {
		next = strchr(line, '\n');
		if (next != NULL) {
			*next = '\0';
		}
		printf("%s%s\n", indent, line);
		if (next == NULL) {
			break;
		}
		line = next + 1;
	}
	free(buf);
}

static const char *text_of(struct blob_attr *table, const char *name, char *buf, size_t len)
{
	value_text(field(table, name), buf, len);
	return buf;
}

static void format_uptime(struct blob_attr *a, char *out, size_t len)
{
	long long s;
	long long d;
	long long h;
	long long m;

	if (a == NULL) {
		snprintf(out, len, "-");
		return;
	}
	if (blobmsg_type(a) == BLOBMSG_TYPE_INT64) {
		s = (long long)blobmsg_get_u64(a);
	} else if (blobmsg_type(a) == BLOBMSG_TYPE_INT32) {
		s = (long long)blobmsg_get_u32(a);
	} else {
		snprintf(out, len, "-");
		return;
	}
	d = s / 86400;
	h = (s / 3600) % 24;
	m = (s / 60) % 60;
	if (d > 0) {
		snprintf(out, len, "%lldd %lldh %lldm", d, h, m);
	} else if (h > 0) {
		snprintf(out, len, "%lldh %lldm", h, m);
	} else {
		snprintf(out, len, "%lldm %llds", m, s % 60);
	}
}

/* "a, b, c" from an array of strings or numbers */
static void join_array(struct blob_attr *a, const char *sep, char *out, size_t len)
{
	struct blob_attr *cur;
	size_t rem;
	size_t used = 0;
	int first = 1;

	out[0] = '\0';
	if (a == NULL || blobmsg_type(a) != BLOBMSG_TYPE_ARRAY) {
		snprintf(out, len, "-");
		return;
	}
	blobmsg_for_each_attr(cur, a, rem) {
		char text[64];
		int n;

		value_text(cur, text, sizeof(text));
		if (first) {
			n = snprintf(out + used, len - used, "%s", text);
		} else {
			n = snprintf(out + used, len - used, "%s%s", sep, text);
		}
		if (n < 0 || (size_t)n >= len - used) {
			break;
		}
		used += (size_t)n;
		first = 0;
	}
	if (first) {
		snprintf(out, len, "-");
	}
}

/* VXLAN column: "<vni>@<device>", or - */
static void add_vxlan(struct apmon_table *t, struct blob_attr *table)
{
	struct blob_attr *vx = field(table, "vxlan");
	char vni[16];
	char dev[32];
	char text[64];

	if (vx == NULL || blobmsg_type(vx) != BLOBMSG_TYPE_TABLE) {
		apmon_table_add(t, "-");
		return;
	}
	value_text(field(vx, "vni"), vni, sizeof(vni));
	value_text(field(vx, "device"), dev, sizeof(dev));
	snprintf(text, sizeof(text), "%s@%s", vni, dev);
	apmon_table_add(t, text);
}

static void add_kbps(struct apmon_table *t, struct blob_attr *c, const char *name)
{
	struct blob_attr *a = field(c, name);
	char text[32];

	if (a == NULL || blobmsg_type(a) != BLOBMSG_TYPE_INT32) {
		apmon_table_add(t, "-");
		return;
	}
	snprintf(text, sizeof(text), "%.1f Mbit/s", (double)(int32_t)blobmsg_get_u32(a) / 1000.0);
	apmon_table_add(t, text);
}

static void add_signal(struct apmon_table *t, struct blob_attr *c)
{
	struct blob_attr *signal = field(c, "signal_avg_dbm");
	char text[32];

	if (signal == NULL || blobmsg_type(signal) != BLOBMSG_TYPE_INT32) {
		signal = field(c, "signal_dbm");
	}
	if (signal != NULL && blobmsg_type(signal) == BLOBMSG_TYPE_INT32) {
		snprintf(text, sizeof(text), "%d dBm", (int32_t)blobmsg_get_u32(signal));
	} else {
		snprintf(text, sizeof(text), "-");
	}
	apmon_table_add(t, text);
}

static void add_where(struct apmon_table *t, struct blob_attr *c)
{
	struct blob_attr *where = field(c, "ap");
	char text[64];

	if (where == NULL || blobmsg_type(where) != BLOBMSG_TYPE_STRING) {
		where = field(c, "port");
	}
	value_text(where, text, sizeof(text));
	apmon_table_add(t, text);
}

static void add_state(struct apmon_table *t, struct blob_attr *c, int *stale)
{
	struct blob_attr *state = field(c, "state");

	if (state != NULL && strcmp(blobmsg_get_string(state), "stale") == 0) {
		apmon_table_add(t, "stale*");
		*stale = *stale + 1;
	} else {
		apmon_table_add(t, "active");
	}
}

/* One node as 1.x show_ap_data: a header block, then its APs and its clients */
static void print_node_block(struct blob_attr *n, int *stale)
{
	struct blob_attr *radios = field(n, "radios");
	struct blob_attr *list = field(n, "clients");
	struct blob_attr *blocks = field(n, "blocks");
	struct blob_attr *def = field(n, "default_passphrase");
	struct blob_attr *r;
	struct blob_attr *c;
	struct apmon_table t;
	char a[64];
	char b[64];
	char c1[64];
	char d[64];
	char e[160];
	char age[16];
	size_t rem;
	size_t rem2;
	int count = 0;

	value_text(field(n, "age_s"), a, sizeof(a));
	apmon_format_age((int64_t)atoll(a), age, sizeof(age));
	printf("=== %s  %s  %s  %s  last report %s ago\n", text_of(n, "hostname", a, sizeof(a)),
	       text_of(n, "node_mac", b, sizeof(b)), text_of(n, "role", c1, sizeof(c1)),
	       text_of(n, "state", d, sizeof(d)), age);

	format_uptime(field(n, "uptime_s"), a, sizeof(a));
	join_array(field(n, "load"), " ", e, sizeof(e));
	printf("    model %s  release %s  apmond %s\n", text_of(n, "model", b, sizeof(b)),
	       text_of(n, "openwrt_release", c1, sizeof(c1)), text_of(n, "apmond_version", d, sizeof(d)));
	printf("    uptime %s  load %s  free RAM %s KiB  free flash %s KiB\n", a, e,
	       text_of(n, "free_ram_kb", b, sizeof(b)), text_of(n, "free_flash_kb", c1, sizeof(c1)));
	join_array(field(n, "ipv4_addresses"), ", ", e, sizeof(e));
	printf("    ULA %s  IPv4 %s\n", text_of(n, "node_ula", a, sizeof(a)), e);
	if (def != NULL && blobmsg_get_bool(def)) {
		snprintf(d, sizeof(d), "DEFAULT");
	} else {
		snprintf(d, sizeof(d), "own");
	}
	printf("    source %s  reports %s  lost %s  passphrase %s\n", text_of(n, "source", a, sizeof(a)),
	       text_of(n, "reports", b, sizeof(b)), text_of(n, "lost_reports", c1, sizeof(c1)), d);
	if (blocks != NULL && blobmsg_len(blocks) > 0) {
		printf("    blocks:");
		blobmsg_for_each_attr(c, blocks, rem) {
			printf(" %s", blobmsg_name(c));
		}
		printf("\n");
	}

	apmon_table_init(&t, 9);
	apmon_table_add(&t, "PHY");
	apmon_table_add(&t, "CHANNEL");
	apmon_table_add(&t, "MHZ");
	apmon_table_add(&t, "HTMODE");
	apmon_table_add(&t, "AP");
	apmon_table_add(&t, "SSID");
	apmon_table_add(&t, "BSSID");
	apmon_table_add(&t, "VLAN");
	apmon_table_add(&t, "VXLAN");
	if (radios != NULL) {
		blobmsg_for_each_attr(r, radios, rem) {
			struct blob_attr *aps = field(r, "aps");
			struct blob_attr *ap;

			if (aps == NULL) {
				continue;
			}
			blobmsg_for_each_attr(ap, aps, rem2) {
				add_field(&t, r, "phy");
				add_field(&t, r, "channel");
				add_field(&t, r, "frequency_mhz");
				add_field(&t, r, "htmode");
				add_field(&t, ap, "ifname");
				add_field(&t, ap, "ssid");
				add_field(&t, ap, "bssid");
				add_field(&t, ap, "vlan");
				add_vxlan(&t, ap);
				count++;
			}
		}
	}
	if (count > 0) {
		printf("  Access points\n");
		print_table_indented(&t, "    ");
	}
	apmon_table_free(&t);

	count = 0;
	apmon_table_init(&t, 11);
	apmon_table_add(&t, "CLIENT_MAC");
	apmon_table_add(&t, "KIND");
	apmon_table_add(&t, "STATE");
	apmon_table_add(&t, "LAST_SEEN");
	apmon_table_add(&t, "WHERE");
	apmon_table_add(&t, "VLAN");
	apmon_table_add(&t, "VXLAN");
	apmon_table_add(&t, "SIGNAL");
	apmon_table_add(&t, "TX");
	apmon_table_add(&t, "RX");
	apmon_table_add(&t, "CONNECTED");
	if (list != NULL) {
		blobmsg_for_each_attr(c, list, rem) {
			struct blob_attr *conn = field(c, "connected_s");

			add_field(&t, c, "client_mac");
			add_field(&t, c, "kind");
			add_state(&t, c, stale);
			add_age(&t, c, "last_seen_age_s");
			add_where(&t, c);
			add_field(&t, c, "vlan");
			add_vxlan(&t, c);
			add_signal(&t, c);
			if (field(c, "speed_mbps") != NULL && blobmsg_type(field(c, "speed_mbps")) == BLOBMSG_TYPE_INT32) {
				/* wired: the link speed both ways, as 1.x */
				snprintf(e, sizeof(e), "%d Mbit/s", (int32_t)blobmsg_get_u32(field(c, "speed_mbps")));
				apmon_table_add(&t, e);
				apmon_table_add(&t, e);
			} else {
				add_kbps(&t, c, "tx_bitrate_kbps");
				add_kbps(&t, c, "rx_bitrate_kbps");
			}
			format_uptime(conn, a, sizeof(a));
			apmon_table_add(&t, a);
			count++;
		}
	}
	if (count > 0) {
		printf("  Clients (%d)\n", count);
		print_table_indented(&t, "    ");
	} else {
		printf("  No clients\n");
	}
	apmon_table_free(&t);
	printf("\n");
}

static int show_nodes(const char *method, struct blob_attr *args)
{
	struct blob_attr *msg;
	struct blob_attr *list;
	struct blob_attr *n;
	size_t rem;
	int stale = 0;
	int ret = call(method, args, &msg);

	if (ret != 0) {
		fprintf(stderr, "%s failed: %s\n", method, ubus_strerror(ret));
		free(msg);
		return 1;
	}
	if (!table_mode) {
		print_json(msg);
		free(msg);
		return 0;
	}

	list = top_field(msg, "nodes");
	if (list != NULL) {
		blobmsg_for_each_attr(n, list, rem) {
			print_node_block(n, &stale);
		}
	} else {
		/* node <id>: the reply is the node table itself */
		struct blob_buf b;

		memset(&b, 0, sizeof(b));
		blob_buf_init(&b, 0);
		blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "node", blob_data(msg), blob_len(msg));
		print_node_block(blob_data(b.head), &stale);
		blob_buf_free(&b);
	}
	if (stale > 0) {
		printf("* stale: not in its node's latest report, kept until client_stale_timeout\n");
	}
	free(msg);
	return 0;
}

static int cmd_nodes(void)
{
	return show_nodes("nodes", NULL);
}

static int cmd_clients(const char *node)
{
	struct blob_buf b;
	struct blob_attr *msg;
	struct blob_attr *list;
	struct blob_attr *c;
	struct apmon_table t;
	size_t rem;
	int stale = 0;
	int ret;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	if (node != NULL) {
		blobmsg_add_string(&b, "node_mac", node);
	}
	ret = call("clients", b.head, &msg);
	blob_buf_free(&b);

	if (ret != 0) {
		fprintf(stderr, "clients failed: %s\n", ubus_strerror(ret));
		free(msg);
		return 1;
	}
	if (!table_mode) {
		print_json(msg);
		free(msg);
		return 0;
	}

	apmon_table_init(&t, 8);
	apmon_table_add(&t, "CLIENT_MAC");
	apmon_table_add(&t, "NODE_MAC");
	apmon_table_add(&t, "HOSTNAME");
	apmon_table_add(&t, "KIND");
	apmon_table_add(&t, "STATE");
	apmon_table_add(&t, "LAST_SEEN");
	apmon_table_add(&t, "WHERE");
	apmon_table_add(&t, "SIGNAL");

	list = top_field(msg, "clients");
	if (list != NULL) {
		blobmsg_for_each_attr(c, list, rem) {
			struct blob_attr *state = field(c, "state");
			struct blob_attr *where = field(c, "ap");
			struct blob_attr *signal = field(c, "signal_avg_dbm");
			char text[64];

			add_field(&t, c, "client_mac");
			add_field(&t, c, "node_mac");
			add_field(&t, c, "node_hostname");
			add_field(&t, c, "kind");
			if (state != NULL && strcmp(blobmsg_get_string(state), "stale") == 0) {
				apmon_table_add(&t, "stale*");
				stale++;
			} else {
				apmon_table_add(&t, "active");
			}
			add_age(&t, c, "last_seen_age_s");

			if (where == NULL || blobmsg_type(where) != BLOBMSG_TYPE_STRING) {
				where = field(c, "port");
			}
			value_text(where, text, sizeof(text));
			apmon_table_add(&t, text);

			if (signal == NULL || blobmsg_type(signal) == BLOBMSG_TYPE_UNSPEC) {
				signal = field(c, "signal_dbm");
			}
			if (signal != NULL && blobmsg_type(signal) == BLOBMSG_TYPE_INT32) {
				snprintf(text, sizeof(text), "%d dBm", (int32_t)blobmsg_get_u32(signal));
			} else {
				snprintf(text, sizeof(text), "-");
			}
			apmon_table_add(&t, text);
		}
	}
	print_table(&t);
	if (stale > 0) {
		printf("* stale: not in its node's latest report, kept until client_stale_timeout\n");
	}
	apmon_table_free(&t);
	free(msg);
	return 0;
}

static int cmd_node(const char *id)
{
	struct blob_buf b;
	int ret;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "node_mac", id);
	ret = show_nodes("node", b.head);
	blob_buf_free(&b);
	return ret;
}

static int simple_call(const char *method, struct blob_attr *args)
{
	struct blob_attr *msg;
	int ret = call(method, args, &msg);

	if (ret != 0) {
		fprintf(stderr, "%s failed: %s\n", method, ubus_strerror(ret));
		free(msg);
		return 1;
	}
	print_json(msg);
	free(msg);
	return 0;
}

static int cmd_block(int argc, char **argv)
{
	struct blob_buf b;
	int ret;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);

	if (argc >= 3 && argc <= 4 && strcmp(argv[0], "add") == 0) {
		void *t;

		blobmsg_add_string(&b, "name", argv[1]);
		t = blobmsg_open_table(&b, "data");
		if (!blobmsg_add_json_from_string(&b, argv[2])) {
			fprintf(stderr, "data must be a JSON object, for example '{\"links\":3}'\n");
			blob_buf_free(&b);
			return 1;
		}
		blobmsg_close_table(&b, t);
		if (argc == 4) {
			blobmsg_add_u32(&b, "ttl", (uint32_t)atoi(argv[3]));
		}
		ret = simple_call("add_block", b.head);
	} else if (argc == 2 && strcmp(argv[0], "remove") == 0) {
		blobmsg_add_string(&b, "name", argv[1]);
		ret = simple_call("remove_block", b.head);
	} else {
		fprintf(stderr, "usage: apmond block add <name> <json> [ttl] | apmond block remove <name>\n");
		ret = 1;
	}
	blob_buf_free(&b);
	return ret;
}

static int cmd_forget(const char *what)
{
	struct blob_buf b;
	struct blob_attr *msg = NULL;
	int ret;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "node_mac", what);
	ret = call("forget", b.head, &msg);

	if (ret == UBUS_STATUS_NOT_FOUND) {
		free(msg);
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "client_mac", what);
		ret = call("forget", b.head, &msg);
	}
	blob_buf_free(&b);

	if (ret != 0) {
		fprintf(stderr, "forget %s: %s\n", what, ubus_strerror(ret));
		free(msg);
		return 1;
	}
	print_json(msg);
	free(msg);
	return 0;
}

int apmond_cli(int argc, char **argv)
{
	char *args[16];
	int n = 0;
	int i;

	for (i = 1; i < argc && n < 16; i++) {
		if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--table") == 0) {
			table_mode = 1;
			continue;
		}
		args[n] = argv[i];
		n++;
	}

	if (n == 0 || strcmp(args[0], "help") == 0 || strcmp(args[0], "-h") == 0 || strcmp(args[0], "--help") == 0) {
		usage();
		if (n == 0) {
			return 1;
		}
		return 0;
	}

	if (strcmp(args[0], "status") == 0 && n == 1) {
		return show_key_values("status", NULL, NULL);
	}
	if (strcmp(args[0], "nodes") == 0 && n == 1) {
		return cmd_nodes();
	}
	if (strcmp(args[0], "clients") == 0 && n <= 2) {
		if (n == 2) {
			return cmd_clients(args[1]);
		}
		return cmd_clients(NULL);
	}
	if (strcmp(args[0], "node") == 0 && n == 2) {
		return cmd_node(args[1]);
	}
	if (strcmp(args[0], "block") == 0 && n >= 2) {
		return cmd_block(n - 1, args + 1);
	}
	if (strcmp(args[0], "forget") == 0 && n == 2) {
		return cmd_forget(args[1]);
	}
	if (strcmp(args[0], "read_log") == 0 && n <= 2) {
		int follow = 0;

		if (n == 2 && strcmp(args[1], "-f") == 0) {
			follow = 1;
		}

		apmond.cfg.debuglevel = 0;
		apmond_config_load(&apmond.cfg, NULL);
		return apmond_read_log(follow);
	}

	usage();
	return 1;
}
