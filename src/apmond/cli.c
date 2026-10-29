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

static void print_json(struct blob_attr *msg)
{
	char *json;

	if (msg == NULL) {
		return;
	}
	json = blobmsg_format_json_indent(msg, true, 0);
	if (json != NULL) {
		printf("%s\n", json);
		free(json);
	}
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

static int cmd_nodes(void)
{
	struct blob_attr *msg;
	struct blob_attr *list;
	struct blob_attr *n;
	struct apmon_table t;
	size_t rem;
	int ret = call("nodes", NULL, &msg);

	if (ret != 0) {
		fprintf(stderr, "nodes failed: %s\n", ubus_strerror(ret));
		free(msg);
		return 1;
	}
	if (!table_mode) {
		print_json(msg);
		free(msg);
		return 0;
	}

	apmon_table_init(&t, 9);
	apmon_table_add(&t, "ID");
	apmon_table_add(&t, "HOSTNAME");
	apmon_table_add(&t, "ROLE");
	apmon_table_add(&t, "STATE");
	apmon_table_add(&t, "AGE");
	apmon_table_add(&t, "CLIENTS");
	apmon_table_add(&t, "LOST");
	apmon_table_add(&t, "SOURCE");
	apmon_table_add(&t, "PASSPHRASE");

	list = top_field(msg, "nodes");
	if (list != NULL) {
		blobmsg_for_each_attr(n, list, rem) {
			struct blob_attr *def = field(n, "default_passphrase");

			add_field(&t, n, "id");
			add_field(&t, n, "hostname");
			add_field(&t, n, "role");
			add_field(&t, n, "state");
			add_age(&t, n, "age_s");
			add_field(&t, n, "clients");
			add_field(&t, n, "lost_reports");
			add_field(&t, n, "source");
			if (def != NULL && blobmsg_get_bool(def)) {
				apmon_table_add(&t, "DEFAULT");
			} else {
				apmon_table_add(&t, "own");
			}
		}
	}
	print_table(&t);
	apmon_table_free(&t);
	free(msg);
	return 0;
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
		blobmsg_add_string(&b, "node", node);
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

	apmon_table_init(&t, 7);
	apmon_table_add(&t, "MAC");
	apmon_table_add(&t, "NODE");
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

			add_field(&t, c, "mac");
			add_field(&t, c, "node");
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
	blobmsg_add_string(&b, "id", id);
	ret = show_key_values("node", b.head, NULL);
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
	blobmsg_add_string(&b, "node", what);
	ret = call("forget", b.head, &msg);

	if (ret == UBUS_STATUS_NOT_FOUND) {
		free(msg);
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "client", what);
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
