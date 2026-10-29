/*
 * apmond collector: libmicrohttpd listener on uloop, message checks, node/client store, ubus object
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include <microhttpd.h>
#include <libubox/avl-cmp.h>
#include <libubox/avl.h>
#include <libubox/blobmsg_json.h>

#include "apmond.h"

struct node {
	struct avl_node avl;
	char id[18];
	char source[64];
	struct blob_attr *report;      /* blob container of the last report's fields */
	uint64_t received_ms;
	uint64_t reports;
	uint32_t last_seq;
	uint64_t lost;
	int default_passphrase;
};

struct client {
	struct avl_node avl;
	char mac[18];
	char node[18];
	char kind[8];
	int64_t last_seen;
	uint64_t node_report;          /* node->reports when this client was last in that node's report */
	struct blob_attr *data;        /* the client's table from the report */
};

struct request {
	uint8_t *body;
	size_t len;
	size_t cap;
	int too_large;
};

static struct MHD_Daemon *mhd;
static struct uloop_fd mhd_fd;
static struct uloop_timeout mhd_timer;
static struct apmon_replay replay;
static struct avl_tree nodes;
static struct avl_tree clients;
static uint32_t response_seq;
static uint64_t count_accepted;
static uint64_t count_auth;
static uint64_t count_conflict;
static uint64_t count_bad;
static struct blob_buf bb;

/* ---------- store ---------- */

static struct node *node_get(const char *id)
{
	struct node *n = avl_find_element(&nodes, id, n, avl);

	if (n != NULL) {
		return n;
	}
	n = calloc(1, sizeof(*n));
	if (n == NULL) {
		return NULL;
	}
	snprintf(n->id, sizeof(n->id), "%s", id);
	n->avl.key = n->id;
	avl_insert(&nodes, &n->avl);
	LOG_NOTICE_("new node %s", id);
	return n;
}

static void client_delete(struct client *c)
{
	avl_delete(&clients, &c->avl);
	free(c->data);
	free(c);
}

static const char *table_string(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, table, rem) {
		if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING && strcmp(blobmsg_name(cur), name) == 0) {
			return blobmsg_get_string(cur);
		}
	}
	return NULL;
}

static int64_t table_int(struct blob_attr *table, const char *name, int64_t def)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, table, rem) {
		if (strcmp(blobmsg_name(cur), name) != 0) {
			continue;
		}
		if (blobmsg_type(cur) == BLOBMSG_TYPE_INT32) {
			return (int32_t)blobmsg_get_u32(cur);
		}
		if (blobmsg_type(cur) == BLOBMSG_TYPE_INT64) {
			return (int64_t)blobmsg_get_u64(cur);
		}
		if (blobmsg_type(cur) == BLOBMSG_TYPE_DOUBLE) {
			return (int64_t)blobmsg_get_double(cur);
		}
	}
	return def;
}

static int client_is_active(struct client *c)
{
	struct node *n = avl_find_element(&nodes, c->node, n, avl);

	return n != NULL && n->reports == c->node_report;
}

static void clients_prune(uint64_t now_ms)
{
	struct client *c;
	struct client *tmp;
	int64_t limit = (int64_t)apmond.cfg.client_stale_timeout * 1000;

	avl_for_each_element_safe(&clients, c, avl, tmp) {
		if (client_is_active(c)) {
			continue;
		}
		if ((int64_t)now_ms - c->last_seen > limit) {
			client_delete(c);
		}
	}
}

static void store_client(struct node *n, struct blob_attr *table, uint64_t now_ms)
{
	const char *mac = table_string(table, "mac");
	const char *kind = table_string(table, "kind");
	int64_t last_seen = table_int(table, "last_seen", (int64_t)now_ms);
	struct client *c;

	if (mac == NULL || kind == NULL || strlen(mac) != 17) {
		return;
	}

	/* An apmond node seen in a bridge fdb is infrastructure, not a client */
	if (avl_find_element(&nodes, mac, (struct node *)NULL, avl) != NULL) {
		return;
	}

	c = avl_find_element(&clients, mac, c, avl);

	/* Wired sightings of a Wi-Fi client (via the uplink port) do not replace its Wi-Fi entry */
	if (c != NULL && strcmp(kind, "wired") == 0 && strcmp(c->kind, "wifi") == 0) {
		int64_t limit = (int64_t)apmond.cfg.client_stale_timeout * 1000;

		if ((int64_t)now_ms - c->last_seen < limit) {
			return;
		}
	}

	if (c == NULL) {
		c = calloc(1, sizeof(*c));
		if (c == NULL) {
			return;
		}
		snprintf(c->mac, sizeof(c->mac), "%s", mac);
		c->avl.key = c->mac;
		avl_insert(&clients, &c->avl);
	} else if (strcmp(c->node, n->id) != 0 && c->node[0] != '\0') {
		LOG_INFO_("client %s moved from %s to %s", mac, c->node, n->id);
	}

	snprintf(c->node, sizeof(c->node), "%s", n->id);
	snprintf(c->kind, sizeof(c->kind), "%s", kind);
	if (last_seen > c->last_seen) {
		c->last_seen = last_seen;
	}
	c->node_report = n->reports;
	free(c->data);
	c->data = blob_memdup(table);
}

static int store_report(const struct apmon_header *h, const char *json, const char *source, uint64_t now_ms)
{
	struct blob_buf b;
	struct blob_attr *cur;
	struct node *n;
	char id[18];
	size_t rem;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_string(&b, json)) {
		blob_buf_free(&b);
		return -1;
	}

	apmon_mac_format(h->sender_id, id);
	n = node_get(id);
	if (n == NULL) {
		blob_buf_free(&b);
		return -1;
	}

	if (n->reports > 0 && h->seq != n->last_seq + 1) {
		uint32_t gap = h->seq - n->last_seq - 1;

		/* a large gap means the sender restarted with a new random seq: not counted as lost */
		if (gap < 1000) {
			n->lost += gap;
		}
	}
	n->last_seq = h->seq;
	n->reports++;
	n->received_ms = now_ms;
	n->default_passphrase = (h->flags & APMON_FLAG_DEFAULT_PASSPHRASE) != 0;
	snprintf(n->source, sizeof(n->source), "%s", source);
	free(n->report);
	n->report = blob_memdup(b.head);

	blob_for_each_attr(cur, b.head, rem) {
		struct blob_attr *entry;
		size_t erem;

		if (strcmp(blobmsg_name(cur), "clients") != 0 || blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY) {
			continue;
		}
		blobmsg_for_each_attr(entry, cur, erem) {
			if (blobmsg_type(entry) == BLOBMSG_TYPE_TABLE) {
				store_client(n, entry, now_ms);
			}
		}
	}

	blob_buf_free(&b);
	clients_prune(now_ms);
	return 0;
}

/* ---------- message processing ---------- */

static int seal_reply(uint8_t type, const char *json, uint8_t **resp, size_t *resp_len)
{
	struct apmon_header h;

	memset(&h, 0, sizeof(h));
	h.type = type;
	if (apmond.cfg.default_seed) {
		h.flags = APMON_FLAG_DEFAULT_PASSPHRASE;
	}
	h.key_epoch = apmond.keys.epoch;
	memcpy(h.sender_id, apmond.id, APMON_ID_LEN);
	h.timestamp_ms = apmon_now_ms();
	h.seq = response_seq;
	response_seq++;

	if (apmon_seal(apmond.keys.c2s, &h, json, strlen(json), resp, resp_len) != APMON_OK) {
		return -1;
	}
	return 0;
}

int apmond_collector_process(int is_time, const uint8_t *body, size_t len, const char *source,
			     uint8_t **resp, size_t *resp_len)
{
	struct apmon_header h;
	enum apmon_result res;
	char *pt = NULL;
	char nonce_hex[2 * APMON_NONCE_LEN + 1];
	char json[256];
	uint64_t now = apmon_now_ms();
	uint8_t expected_type = APMON_TYPE_REPORT;

	*resp = NULL;
	*resp_len = 0;

	if (is_time) {
		expected_type = APMON_TYPE_TIME_REQ;
	}

	res = apmon_header_decode(body, len, &h);
	if (res == APMON_ERR_VERSION) {
		count_bad++;
		return 426;
	}
	if (res != APMON_OK) {
		count_bad++;
		return 400;
	}
	if (h.key_epoch != apmond.keys.epoch) {
		count_auth++;
		return 401;
	}

	res = apmon_open(apmond.keys.s2c, body, len, &h, &pt, NULL);
	if (res != APMON_OK) {
		count_auth++;
		LOG_INFO_("message from %s failed authentication (different apmon_seed?)", source);
		return 401;
	}
	if (h.type != expected_type) {
		count_bad++;
		free(pt);
		return 400;
	}

	apmon_hex_encode(h.nonce, APMON_NONCE_LEN, nonce_hex);

	res = apmon_replay_check(&replay, &h, now, !is_time);
	if (res != APMON_OK) {
		count_conflict++;
		free(pt);
		snprintf(json, sizeof(json),
			 "{\"v\":2,\"type\":\"error\",\"code\":\"%s\",\"collector_time\":%llu,\"echo_nonce\":\"%s\"}",
			 res == APMON_ERR_TIME ? "time" : "replay", (unsigned long long)now, nonce_hex);
		seal_reply(APMON_TYPE_ERROR, json, resp, resp_len);
		return 409;
	}

	if (is_time) {
		free(pt);
		snprintf(json, sizeof(json),
			 "{\"v\":2,\"type\":\"time_resp\",\"collector_time\":%llu,\"echo_nonce\":\"%s\"}",
			 (unsigned long long)now, nonce_hex);
		if (seal_reply(APMON_TYPE_TIME_RESP, json, resp, resp_len) != 0) {
			return 500;
		}
		return 200;
	}

	if (store_report(&h, pt, source, now) != 0) {
		count_bad++;
		free(pt);
		return 400;
	}
	free(pt);
	count_accepted++;

	snprintf(json, sizeof(json),
		 "{\"v\":2,\"type\":\"ack\",\"status\":\"ok\",\"collector_time\":%llu,\"echo_nonce\":\"%s\",\"interval\":%d}",
		 (unsigned long long)now, nonce_hex, apmond.cfg.interval);
	if (seal_reply(APMON_TYPE_ACK, json, resp, resp_len) != 0) {
		return 500;
	}
	return 200;
}

/* ---------- libmicrohttpd ---------- */

static enum MHD_Result reply(struct MHD_Connection *conn, unsigned int status, uint8_t *body, size_t len)
{
	struct MHD_Response *r;
	enum MHD_Result ret;

	if (body != NULL) {
		r = MHD_create_response_from_buffer(len, body, MHD_RESPMEM_MUST_FREE);
		MHD_add_response_header(r, MHD_HTTP_HEADER_CONTENT_TYPE, APMON_CONTENT_TYPE);
	} else {
		r = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
	}
	if (r == NULL) {
		free(body);
		return MHD_NO;
	}
	ret = MHD_queue_response(conn, status, r);
	MHD_destroy_response(r);
	return ret;
}

static void source_address(struct MHD_Connection *conn, char *out, size_t out_len)
{
	const union MHD_ConnectionInfo *info = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
	const struct sockaddr *sa;

	snprintf(out, out_len, "unknown");
	if (info == NULL || info->client_addr == NULL) {
		return;
	}
	sa = info->client_addr;
	if (sa->sa_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, out, (socklen_t)out_len);
	} else if (sa->sa_family == AF_INET6) {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, out, (socklen_t)out_len);
	}
}

static enum MHD_Result on_request(void *cls, struct MHD_Connection *conn, const char *url, const char *method,
				  const char *version, const char *upload_data, size_t *upload_data_size,
				  void **con_cls)
{
	struct request *req = *con_cls;
	const char *ctype;
	const char *clen;
	int is_time;

	(void)cls;
	(void)version;

	if (req == NULL) {
		/* First call: headers only */
		if (strcmp(url, APMON_PATH_REPORT) != 0 && strcmp(url, APMON_PATH_TIME) != 0) {
			return reply(conn, MHD_HTTP_NOT_FOUND, NULL, 0);
		}
		if (strcmp(method, MHD_HTTP_METHOD_POST) != 0) {
			return reply(conn, MHD_HTTP_METHOD_NOT_ALLOWED, NULL, 0);
		}
		ctype = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_TYPE);
		if (ctype == NULL || strcmp(ctype, APMON_CONTENT_TYPE) != 0) {
			return reply(conn, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, NULL, 0);
		}
		clen = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
		if (clen == NULL || strtoul(clen, NULL, 10) > (unsigned long)apmond.cfg.max_message_size) {
			return reply(conn, MHD_HTTP_CONTENT_TOO_LARGE, NULL, 0);
		}

		req = calloc(1, sizeof(*req));
		if (req == NULL) {
			return MHD_NO;
		}
		*con_cls = req;
		return MHD_YES;
	}

	if (*upload_data_size > 0) {
		size_t n = *upload_data_size;

		if (req->len + n > (size_t)apmond.cfg.max_message_size) {
			req->too_large = 1;
		} else {
			if (req->len + n > req->cap) {
				size_t cap = req->len + n;
				uint8_t *nb = realloc(req->body, cap);

				if (nb == NULL) {
					return MHD_NO;
				}
				req->body = nb;
				req->cap = cap;
			}
			memcpy(req->body + req->len, upload_data, n);
			req->len += n;
		}
		*upload_data_size = 0;
		return MHD_YES;
	}

	/* Body complete */
	if (req->too_large) {
		return reply(conn, MHD_HTTP_CONTENT_TOO_LARGE, NULL, 0);
	}

	{
		char source[INET6_ADDRSTRLEN];
		uint8_t *resp = NULL;
		size_t resp_len = 0;
		int status;

		source_address(conn, source, sizeof(source));
		is_time = strcmp(url, APMON_PATH_TIME) == 0;
		status = apmond_collector_process(is_time, req->body, req->len, source, &resp, &resp_len);
		return reply(conn, (unsigned int)status, resp, resp_len);
	}
}

static void on_completed(void *cls, struct MHD_Connection *conn, void **con_cls, enum MHD_RequestTerminationCode toe)
{
	struct request *req = *con_cls;

	(void)cls;
	(void)conn;
	(void)toe;

	if (req != NULL) {
		free(req->body);
		free(req);
		*con_cls = NULL;
	}
}

static void mhd_schedule(void)
{
	MHD_UNSIGNED_LONG_LONG timeout;

	if (MHD_get_timeout(mhd, &timeout) == MHD_YES) {
		if (timeout > 1000) {
			timeout = 1000;
		}
		uloop_timeout_set(&mhd_timer, (int)timeout);
	} else {
		uloop_timeout_cancel(&mhd_timer);
	}
}

static void mhd_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	(void)fd;
	(void)events;
	MHD_run(mhd);
	mhd_schedule();
}

static void mhd_timer_cb(struct uloop_timeout *t)
{
	(void)t;
	MHD_run(mhd);
	mhd_schedule();
}

int apmond_collector_running(void)
{
	return mhd != NULL;
}

int apmond_collector_start(void)
{
	const union MHD_DaemonInfo *info;
	size_t replay_size = 4096;

	if (mhd != NULL) {
		return 0;
	}

	if (apmon_replay_init(&replay, replay_size, (uint64_t)apmond.cfg.max_age * 1000) != 0) {
		return -1;
	}

	mhd = MHD_start_daemon(MHD_USE_EPOLL | MHD_USE_DUAL_STACK, (uint16_t)apmond.cfg.port, NULL, NULL,
			       on_request, NULL,
			       MHD_OPTION_NOTIFY_COMPLETED, on_completed, NULL,
			       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)15,
			       MHD_OPTION_CONNECTION_LIMIT, (unsigned int)32,
			       MHD_OPTION_END);
	if (mhd == NULL) {
		LOG_ERR_("could not listen on port %d", apmond.cfg.port);
		apmon_replay_free(&replay);
		return -1;
	}

	info = MHD_get_daemon_info(mhd, MHD_DAEMON_INFO_EPOLL_FD);
	if (info == NULL) {
		LOG_ERR_("libmicrohttpd has no epoll support");
		MHD_stop_daemon(mhd);
		mhd = NULL;
		return -1;
	}

	mhd_fd.fd = info->epoll_fd;
	mhd_fd.cb = mhd_fd_cb;
	uloop_fd_add(&mhd_fd, ULOOP_READ);
	mhd_timer.cb = mhd_timer_cb;
	mhd_schedule();

	LOG_NOTICE_("collector listening on port %d", apmond.cfg.port);
	return 0;
}

/* ---------- ubus object "apmond" ---------- */

static const char *role_name(void)
{
	if (apmond.role == ROLE_COLLECTOR) {
		return "collector";
	}
	if (apmond.role == ROLE_SENDER) {
		return "sender";
	}
	return "unknown";
}

static int ubus_status(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		       const char *method, struct blob_attr *msg)
{
	(void)obj;
	(void)method;
	(void)msg;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "version", APMOND_VERSION);
	blobmsg_add_u32(&bb, "protocol", APMON_VERSION);
	blobmsg_add_string(&bb, "id", apmond.id_str);
	blobmsg_add_string(&bb, "role", role_name());
	blobmsg_add_u32(&bb, "port", (uint32_t)apmond.cfg.port);
	blobmsg_add_u32(&bb, "key_epoch", apmond.keys.epoch);
	blobmsg_add_u8(&bb, "default_passphrase", (uint8_t)apmond.cfg.default_seed);
	if (apmond.cfg.default_seed) {
		blobmsg_add_string(&bb, "passphrase_warning",
				   "The built-in default passphrase is in use. Set option apmon_seed in /etc/config/apmond "
				   "(the same on every node) to secure apmond");
	}
	if (apmond.role == ROLE_SENDER) {
		blobmsg_add_string(&bb, "collector", apmond.collector_addr);
	}
	blobmsg_add_u8(&bb, "clock_synced", (uint8_t)apmond.time_synced);
	blobmsg_add_u64(&bb, "reports_sent", apmond.reports_sent);
	blobmsg_add_u64(&bb, "reports_failed", apmond.reports_failed);
	blobmsg_add_u32(&bb, "last_status", (uint32_t)apmond.last_status);
	if (apmond.role == ROLE_COLLECTOR) {
		void *c = blobmsg_open_table(&bb, "collector_counters");

		blobmsg_add_u64(&bb, "accepted", count_accepted);
		blobmsg_add_u64(&bb, "auth_failed", count_auth);
		blobmsg_add_u64(&bb, "rejected_time_or_replay", count_conflict);
		blobmsg_add_u64(&bb, "malformed", count_bad);
		blobmsg_close_table(&bb, c);
		blobmsg_add_u32(&bb, "nodes", (uint32_t)nodes.count);
		blobmsg_add_u32(&bb, "clients", (uint32_t)clients.count);
	}
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

/* Age in ms, 0 if the wall clock stepped backwards since */
static uint64_t age_ms(uint64_t now, uint64_t then)
{
	if (now < then) {
		return 0;
	}
	return now - then;
}

static const char *node_state(struct node *n, uint64_t now)
{
	uint64_t age = age_ms(now, n->received_ms);
	uint64_t interval = (uint64_t)apmond.cfg.interval * 1000;

	if (age <= 2 * interval) {
		return "ok";
	}
	if (age <= 5 * interval) {
		return "late";
	}
	return "lost";
}

static int count_node_clients(const char *id)
{
	struct client *c;
	int count = 0;

	avl_for_each_element(&clients, c, avl) {
		if (strcmp(c->node, id) == 0 && client_is_active(c)) {
			count++;
		}
	}
	return count;
}

static int ubus_nodes(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	struct node *n;
	uint64_t now = apmon_now_ms();
	void *arr;

	(void)obj;
	(void)method;
	(void)msg;

	blob_buf_init(&bb, 0);
	arr = blobmsg_open_array(&bb, "nodes");
	avl_for_each_element(&nodes, n, avl) {
		void *t = blobmsg_open_table(&bb, NULL);
		struct blob_attr *cur;
		size_t rem;

		blobmsg_add_string(&bb, "id", n->id);
		blob_for_each_attr(cur, n->report, rem) {
			const char *host;
			const char *role;

			if (strcmp(blobmsg_name(cur), "node") != 0) {
				continue;
			}
			host = table_string(cur, "hostname");
			role = table_string(cur, "role");

			if (host != NULL) {
				blobmsg_add_string(&bb, "hostname", host);
			}
			if (role != NULL) {
				blobmsg_add_string(&bb, "role", role);
			}
		}
		blobmsg_add_string(&bb, "source", n->source);
		blobmsg_add_u64(&bb, "last_report", n->received_ms);
		blobmsg_add_u32(&bb, "age_s", (uint32_t)(age_ms(now, n->received_ms) / 1000));
		blobmsg_add_string(&bb, "state", node_state(n, now));
		blobmsg_add_u64(&bb, "reports", n->reports);
		blobmsg_add_u64(&bb, "lost_reports", n->lost);
		blobmsg_add_u32(&bb, "clients", (uint32_t)count_node_clients(n->id));
		blobmsg_add_u8(&bb, "default_passphrase", (uint8_t)n->default_passphrase);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, arr);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

enum {
	NODE_ID,
	__NODE_MAX,
};

static const struct blobmsg_policy node_policy[__NODE_MAX] = {
	[NODE_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_node(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		     const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__NODE_MAX];
	struct node *n;

	(void)obj;
	(void)method;

	blobmsg_parse(node_policy, __NODE_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[NODE_ID] == NULL) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	n = avl_find_element(&nodes, blobmsg_get_string(tb[NODE_ID]), n, avl);
	if (n == NULL || n->report == NULL) {
		return UBUS_STATUS_NOT_FOUND;
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "id", n->id);
	blobmsg_add_string(&bb, "source", n->source);
	blobmsg_add_u64(&bb, "received", n->received_ms);
	blobmsg_add_field(&bb, BLOBMSG_TYPE_TABLE, "report", blob_data(n->report), blob_len(n->report));
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

enum {
	CLIENTS_NODE,
	CLIENTS_STALE,
	__CLIENTS_MAX,
};

static const struct blobmsg_policy clients_policy[__CLIENTS_MAX] = {
	[CLIENTS_NODE] = { .name = "node", .type = BLOBMSG_TYPE_STRING },
	[CLIENTS_STALE] = { .name = "include_stale", .type = BLOBMSG_TYPE_BOOL },
};

static int ubus_clients(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENTS_MAX];
	const char *only_node = NULL;
	int include_stale = 1;
	struct client *c;
	uint64_t now = apmon_now_ms();
	void *arr;

	(void)obj;
	(void)method;

	blobmsg_parse(clients_policy, __CLIENTS_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[CLIENTS_NODE] != NULL) {
		only_node = blobmsg_get_string(tb[CLIENTS_NODE]);
	}
	if (tb[CLIENTS_STALE] != NULL) {
		include_stale = blobmsg_get_bool(tb[CLIENTS_STALE]);
	}

	clients_prune(now);

	blob_buf_init(&bb, 0);
	arr = blobmsg_open_array(&bb, "clients");
	avl_for_each_element(&clients, c, avl) {
		int active = client_is_active(c);
		struct blob_attr *cur;
		size_t rem;
		void *t;

		if (only_node != NULL && strcmp(only_node, c->node) != 0) {
			continue;
		}
		if (!active && !include_stale) {
			continue;
		}

		t = blobmsg_open_table(&bb, NULL);
		blobmsg_add_string(&bb, "node", c->node);
		if (active) {
			blobmsg_add_string(&bb, "state", "active");
		} else {
			blobmsg_add_string(&bb, "state", "stale");
		}
		if (c->last_seen > 0) {
			blobmsg_add_u32(&bb, "last_seen_age_s", (uint32_t)(age_ms(now, (uint64_t)c->last_seen) / 1000));
		}
		blobmsg_for_each_attr(cur, c->data, rem) {
			blobmsg_add_blob(&bb, cur);
		}
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, arr);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static const struct ubus_method apmond_methods[] = {
	UBUS_METHOD_NOARG("status", ubus_status),
	UBUS_METHOD_NOARG("nodes", ubus_nodes),
	UBUS_METHOD("node", ubus_node, node_policy),
	UBUS_METHOD("clients", ubus_clients, clients_policy),
};

static struct ubus_object_type apmond_object_type = UBUS_OBJECT_TYPE("apmond", apmond_methods);

static struct ubus_object apmond_object = {
	.name = "apmond",
	.type = &apmond_object_type,
	.methods = apmond_methods,
	.n_methods = ARRAY_SIZE(apmond_methods),
};

void apmond_ubus_init(void)
{
	avl_init(&nodes, avl_strcmp, false, NULL);
	avl_init(&clients, avl_strcmp, false, NULL);

	if (apmond.ubus == NULL) {
		return;
	}
	if (ubus_add_object(apmond.ubus, &apmond_object) != 0) {
		LOG_ERR_("could not register ubus object apmond");
	}
}
