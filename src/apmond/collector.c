/*
 * apmond collector: libmicrohttpd listener on uloop, message checks, node/client store, ubus object
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
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
	int lost_reported;
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
static struct blob_buf ev;
static const struct apmon_keys *reply_keys;
static int listen_fd = -1;

static uint64_t age_ms(uint64_t now, uint64_t then);
static const char *node_state(struct node *n, uint64_t now);

/* ---------- store ---------- */

static void send_event(const char *type, const char *key1, const char *val1, const char *key2, const char *val2,
		       const char *key3, const char *val3)
{
	if (apmond.ubus == NULL) {
		return;
	}
	blob_buf_init(&ev, 0);
	blobmsg_add_string(&ev, key1, val1);
	if (key2 != NULL) {
		blobmsg_add_string(&ev, key2, val2);
	}
	if (key3 != NULL) {
		blobmsg_add_string(&ev, key3, val3);
	}
	ubus_send_event(apmond.ubus, type, ev.head);
}

static struct node *node_get(const char *id, const char *source)
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
	send_event("apmond.node.new", "id", id, "source", source, NULL, NULL);
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
	const char *mac = table_string(table, "client_mac");
	const char *kind = table_string(table, "kind");
	int64_t last_seen = table_int(table, "last_seen", (int64_t)now_ms);
	struct client *c;

	/* apmond 2.0 betas before r8 sent "mac" */
	if (mac == NULL) {
		mac = table_string(table, "mac");
	}
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
		send_event("apmond.client.roam", "client_mac", mac, "from", c->node, "to", n->id);
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
	n = node_get(id, source);
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
	n->lost_reported = 0;
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
	h.key_epoch = reply_keys->epoch;
	memcpy(h.sender_id, apmond.id, APMON_ID_LEN);
	h.timestamp_ms = apmon_now_ms();
	h.seq = response_seq;
	response_seq++;

	if (apmon_seal(reply_keys->c2s, &h, json, strlen(json), resp, resp_len) != APMON_OK) {
		return -1;
	}
	return 0;
}

/* Keys for a message's key_epoch: the current one, or the previous one during prev_epoch_grace */
static const struct apmon_keys *select_keys(uint32_t epoch)
{
	uint64_t since_start = apmon_monotonic_ms() - apmond.start_mono_ms;

	if (epoch == apmond.keys.epoch) {
		return &apmond.keys;
	}
	if (apmond.keys.epoch == 0 || epoch != apmond.prev_keys.epoch) {
		return NULL;
	}
	if (since_start > (uint64_t)apmond.cfg.prev_epoch_grace * 1000) {
		return NULL;
	}
	return &apmond.prev_keys;
}

int apmond_collector_process(int is_time, const uint8_t *body, size_t len, const char *source,
			     uint8_t **resp, size_t *resp_len)
{
	struct apmon_header h;
	enum apmon_result res;
	char *pt = NULL;
	char nonce_hex[2 * APMON_NONCE_LEN + 1];
	char sender_mac[18];
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
	reply_keys = select_keys(h.key_epoch);
	if (reply_keys == NULL) {
		count_auth++;
		return 401;
	}

	res = apmon_open(reply_keys->s2c, body, len, &h, &pt, NULL);
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
	apmon_mac_format(h.sender_id, sender_mac);
	LOG_DEBUG_("report %u from %s (%s) accepted", (unsigned int)h.seq, sender_mac, source);

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

/*
 * One dual-stack TCP socket bound to option device (SO_BINDTODEVICE), so the collector answers on its
 * LAN addresses (IPv4 and the ULAs) and not on the WAN.
 */
static int open_listener(void)
{
	struct sockaddr_in6 sa;
	int fd;
	int off = 0;
	int on = 1;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, apmond.cfg.netdev, (socklen_t)strlen(apmond.cfg.netdev)) != 0) {
		LOG_ERR_("cannot bind the listener to %s", apmond.cfg.netdev);
		close(fd);
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons((uint16_t)apmond.cfg.port);
	sa.sin6_addr = in6addr_any;

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 16) != 0) {
		close(fd);
		return -1;
	}
	return fd;
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

	listen_fd = open_listener();
	if (listen_fd < 0) {
		LOG_ERR_("could not listen on port %d on %s", apmond.cfg.port, apmond.cfg.netdev);
		apmon_replay_free(&replay);
		return -1;
	}

	mhd = MHD_start_daemon(MHD_USE_EPOLL, 0, NULL, NULL,
			       on_request, NULL,
			       MHD_OPTION_LISTEN_SOCKET, listen_fd,
			       MHD_OPTION_NOTIFY_COMPLETED, on_completed, NULL,
			       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)15,
			       MHD_OPTION_CONNECTION_LIMIT, (unsigned int)32,
			       MHD_OPTION_END);
	if (mhd == NULL) {
		LOG_ERR_("could not start the listener on port %d", apmond.cfg.port);
		close(listen_fd);
		listen_fd = -1;
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

	LOG_NOTICE_("collector listening on port %d (%s only)", apmond.cfg.port, apmond.cfg.netdev);
	return 0;
}

void apmond_collector_stop(void)
{
	if (mhd == NULL) {
		return;
	}
	uloop_fd_delete(&mhd_fd);
	uloop_timeout_cancel(&mhd_timer);
	MHD_stop_daemon(mhd);
	mhd = NULL;
	if (listen_fd >= 0) {
		close(listen_fd);
		listen_fd = -1;
	}
	apmon_replay_free(&replay);
	LOG_NOTICE_("collector listener stopped");
}

/* Every report interval on the collector: lost-node events and stale client pruning */
void apmond_collector_housekeeping(void)
{
	struct node *n;
	uint64_t now = apmon_now_ms();

	avl_for_each_element(&nodes, n, avl) {
		if (n->lost_reported) {
			continue;
		}
		if (strcmp(node_state(n, now), "lost") == 0) {
			n->lost_reported = 1;
			LOG_NOTICE_("node %s lost (no report for %llu s)", n->id,
				    (unsigned long long)(age_ms(now, n->received_ms) / 1000));
			send_event("apmond.node.lost", "id", n->id, "source", n->source, NULL, NULL);
		}
	}
	clients_prune(now);
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
	blobmsg_add_string(&bb, "role_reason", apmond.role_reason);
	blobmsg_add_string(&bb, "node_ula", apmond.node_ula);
	blobmsg_add_string(&bb, "collector_ula", apmond.router_ula);
	if (apmond.role == ROLE_SENDER) {
		blobmsg_add_string(&bb, "collector_via", apmond.collector_via);
	}
	blobmsg_add_u8(&bb, "clock_synced", (uint8_t)apmond.time_synced);
	blobmsg_add_u64(&bb, "reports_sent", apmond.reports_sent);
	blobmsg_add_u64(&bb, "reports_failed", apmond.reports_failed);
	blobmsg_add_u32(&bb, "last_status", (uint32_t)apmond.last_status);
	blobmsg_add_u32(&bb, "debuglevel", (uint32_t)apmond.cfg.debuglevel);
	apmond_blocks_list(&bb);
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

/* The "node" table of a node's last report, or NULL */
static struct blob_attr *report_part(struct node *n, const char *name)
{
	struct blob_attr *cur;
	size_t rem;

	if (n->report == NULL) {
		return NULL;
	}
	blob_for_each_attr(cur, n->report, rem) {
		if (strcmp(blobmsg_name(cur), name) == 0) {
			return cur;
		}
	}
	return NULL;
}

static const char *node_hostname(struct node *n)
{
	struct blob_attr *info = report_part(n, "node");
	const char *host = NULL;

	if (info != NULL) {
		host = table_string(info, "hostname");
	}
	if (host == NULL) {
		host = "";
	}
	return host;
}

static int node_is_collector(struct node *n)
{
	return strcmp(n->source, "local") == 0;
}

/* Display order, as 1.x show_ap_data: the collector first, then by hostname, then by id */
static int node_order(const void *a, const void *b)
{
	struct node *na = *(struct node *const *)a;
	struct node *nb = *(struct node *const *)b;

	return apmon_node_cmp(node_is_collector(na), node_hostname(na), na->id, node_is_collector(nb),
			      node_hostname(nb), nb->id);
}

/* All nodes in display order; the caller frees the array */
static struct node **sorted_nodes(int *count)
{
	struct node **list;
	struct node *n;
	int i = 0;

	*count = 0;
	list = calloc(nodes.count + 1, sizeof(*list));
	if (list == NULL) {
		return NULL;
	}
	avl_for_each_element(&nodes, n, avl) {
		list[i] = n;
		i++;
	}
	qsort(list, (size_t)i, sizeof(*list), node_order);
	*count = i;
	return list;
}

/* <name>: Unix seconds, and <name>_date: the same as 1.x date_time (local time) */
static void add_time(struct blob_buf *b, const char *name, int64_t unix_ms)
{
	char key[64];
	char date[64];
	int64_t secs = unix_ms / 1000;

	blobmsg_add_u64(b, name, (uint64_t)secs);
	snprintf(key, sizeof(key), "%s_date", name);
	apmon_format_date(secs, date, sizeof(date));
	blobmsg_add_string(b, key, date);
}

/* A field of the client's report, copied as is, if present */
static void copy_field(struct blob_attr *data, const char *name)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, data, rem) {
		if (strcmp(blobmsg_name(cur), name) == 0) {
			blobmsg_add_blob(&bb, cur);
			return;
		}
	}
}

/* A field of one of the node's APs (from its report's radios[].aps[]), or NULL */
static const char *node_ap_field(struct node *n, const char *ifname, const char *name)
{
	struct blob_attr *radios;
	struct blob_attr *r;
	size_t rem;

	if (n == NULL || ifname == NULL) {
		return NULL;
	}
	radios = report_part(n, "radios");
	if (radios == NULL) {
		return NULL;
	}
	blobmsg_for_each_attr(r, radios, rem) {
		struct blob_attr *cur;
		size_t rem2;

		blobmsg_for_each_attr(cur, r, rem2) {
			struct blob_attr *ap;
			size_t rem3;

			if (strcmp(blobmsg_name(cur), "aps") != 0) {
				continue;
			}
			blobmsg_for_each_attr(ap, cur, rem3) {
				const char *name_of_ap = table_string(ap, "ifname");

				if (name_of_ap != NULL && strcmp(name_of_ap, ifname) == 0) {
					return table_string(ap, name);
				}
			}
		}
	}
	return NULL;
}

/*
 * ap_ssid, ap_ifname, ap_bssid of a Wi-Fi client. Senders from r9 report them; for older betas
 * (only "ap": ifname) the SSID and BSSID are looked up in the node's aps.
 */
static void add_client_ap(struct client *c, struct node *n)
{
	const char *ifname = table_string(c->data, "ap_ifname");
	const char *ssid = table_string(c->data, "ap_ssid");
	const char *bssid = table_string(c->data, "ap_bssid");

	if (ifname == NULL) {
		ifname = table_string(c->data, "ap");
	}
	if (ifname == NULL) {
		return;
	}
	if (ssid == NULL) {
		ssid = node_ap_field(n, ifname, "ssid");
	}
	if (bssid == NULL) {
		bssid = node_ap_field(n, ifname, "bssid");
	}
	if (ssid != NULL) {
		blobmsg_add_string(&bb, "ap_ssid", ssid);
	}
	blobmsg_add_string(&bb, "ap_ifname", ifname);
	if (bssid != NULL) {
		blobmsg_add_string(&bb, "ap_bssid", bssid);
	}
}

/*
 * One client: client_mac first, then (flat list only) node_mac and node_hostname, kind, state,
 * last seen (seconds, date, age), where it is (ap, or bridge and port), vlan, vxlan, then the
 * kind-specific stats from its report.
 */
static void add_client(struct client *c, struct node *n, uint64_t now, int with_node)
{
	struct blob_attr *cur;
	size_t rem;
	void *t = blobmsg_open_table(&bb, NULL);

	blobmsg_add_string(&bb, "client_mac", c->mac);
	if (with_node) {
		blobmsg_add_string(&bb, "node_mac", c->node);
		if (n != NULL) {
			blobmsg_add_string(&bb, "node_hostname", node_hostname(n));
		}
	}
	blobmsg_add_string(&bb, "kind", c->kind);
	if (client_is_active(c)) {
		blobmsg_add_string(&bb, "state", "active");
	} else {
		blobmsg_add_string(&bb, "state", "stale");
	}
	if (c->last_seen > 0) {
		/* seconds with a date, as 1.x timestamp/date_time */
		add_time(&bb, "last_seen", c->last_seen);
		blobmsg_add_u32(&bb, "last_seen_age_s", (uint32_t)(age_ms(now, (uint64_t)c->last_seen) / 1000));
	}
	add_client_ap(c, n);
	copy_field(c->data, "bridge");
	copy_field(c->data, "port");
	copy_field(c->data, "vlan");
	copy_field(c->data, "vxlan");

	blobmsg_for_each_attr(cur, c->data, rem) {
		if (apmon_client_ordered_field(blobmsg_name(cur))) {
			continue;
		}
		blobmsg_add_blob(&bb, cur);
	}
	blobmsg_close_table(&bb, t);
}

/*
 * One node with everything it reported (as 1.x node_status: hostname, model, release, version,
 * uptime, load, memory, node_ula, ipv4_addresses), the collector's view of it (state, age,
 * source, counters), its radios/APs, blocks and its clients nested under it, sorted by MAC.
 */
static void add_node_fields(struct node *n, uint64_t now)
{
	struct blob_attr *info = report_part(n, "node");
	struct blob_attr *radios = report_part(n, "radios");
	struct blob_attr *blocks = report_part(n, "blocks");
	struct blob_attr *cur;
	struct client *c;
	size_t rem;
	void *arr;

	blobmsg_add_string(&bb, "node_mac", n->id);
	if (info != NULL) {
		blobmsg_for_each_attr(cur, info, rem) {
			if (strcmp(blobmsg_name(cur), "id") == 0) {
				continue;
			}
			if (strcmp(blobmsg_name(cur), "default_passphrase") == 0) {
				continue;
			}
			blobmsg_add_blob(&bb, cur);
		}
	}
	blobmsg_add_string(&bb, "state", node_state(n, now));
	blobmsg_add_u32(&bb, "age_s", (uint32_t)(age_ms(now, n->received_ms) / 1000));
	add_time(&bb, "last_report", (int64_t)n->received_ms);
	blobmsg_add_string(&bb, "source", n->source);
	blobmsg_add_u64(&bb, "reports", n->reports);
	blobmsg_add_u64(&bb, "lost_reports", n->lost);
	blobmsg_add_u8(&bb, "default_passphrase", (uint8_t)n->default_passphrase);
	blobmsg_add_u32(&bb, "client_count", (uint32_t)count_node_clients(n->id));

	if (radios != NULL) {
		blobmsg_add_blob(&bb, radios);
	} else {
		arr = blobmsg_open_array(&bb, "radios");
		blobmsg_close_array(&bb, arr);
	}
	if (blocks != NULL) {
		blobmsg_add_blob(&bb, blocks);
	} else {
		arr = blobmsg_open_table(&bb, "blocks");
		blobmsg_close_table(&bb, arr);
	}

	arr = blobmsg_open_array(&bb, "clients");
	avl_for_each_element(&clients, c, avl) {
		if (strcmp(c->node, n->id) == 0) {
			add_client(c, n, now, 0);
		}
	}
	blobmsg_close_array(&bb, arr);
}

static int ubus_nodes(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	struct node **list;
	uint64_t now = apmon_now_ms();
	int count;
	int i;
	void *arr;

	(void)obj;
	(void)method;
	(void)msg;

	clients_prune(now);
	list = sorted_nodes(&count);
	if (list == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	blob_buf_init(&bb, 0);
	arr = blobmsg_open_array(&bb, "nodes");
	for (i = 0; i < count; i++) {
		void *t = blobmsg_open_table(&bb, NULL);

		add_node_fields(list[i], now);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, arr);
	free(list);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

enum {
	NODE_ID,
	NODE_MAC,
	__NODE_MAX,
};

static const struct blobmsg_policy node_policy[__NODE_MAX] = {
	[NODE_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
	[NODE_MAC] = { .name = "node_mac", .type = BLOBMSG_TYPE_STRING },
};

/* The single-node form of the nodes structure */
static int ubus_node(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		     const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__NODE_MAX];
	struct node *n;
	uint64_t now = apmon_now_ms();

	(void)obj;
	(void)method;

	blobmsg_parse(node_policy, __NODE_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[NODE_ID] == NULL) {
		tb[NODE_ID] = tb[NODE_MAC];
	}
	if (tb[NODE_ID] == NULL) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	n = avl_find_element(&nodes, blobmsg_get_string(tb[NODE_ID]), n, avl);
	if (n == NULL || n->report == NULL) {
		return UBUS_STATUS_NOT_FOUND;
	}

	clients_prune(now);
	blob_buf_init(&bb, 0);
	add_node_fields(n, now);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

enum {
	CLIENTS_NODE,
	CLIENTS_NODE_MAC,
	CLIENTS_STALE,
	__CLIENTS_MAX,
};

static const struct blobmsg_policy clients_policy[__CLIENTS_MAX] = {
	[CLIENTS_NODE] = { .name = "node", .type = BLOBMSG_TYPE_STRING },
	[CLIENTS_NODE_MAC] = { .name = "node_mac", .type = BLOBMSG_TYPE_STRING },
	[CLIENTS_STALE] = { .name = "include_stale", .type = BLOBMSG_TYPE_BOOL },
};

/* Flat list for scripts, in node display order and then by MAC */
static int ubus_clients(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENTS_MAX];
	const char *only_node = NULL;
	int include_stale = 1;
	struct node **list;
	struct client *c;
	uint64_t now = apmon_now_ms();
	int count;
	int i;
	void *arr;

	(void)obj;
	(void)method;

	blobmsg_parse(clients_policy, __CLIENTS_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[CLIENTS_NODE] == NULL) {
		tb[CLIENTS_NODE] = tb[CLIENTS_NODE_MAC];
	}
	if (tb[CLIENTS_NODE] != NULL) {
		only_node = blobmsg_get_string(tb[CLIENTS_NODE]);
	}
	if (tb[CLIENTS_STALE] != NULL) {
		include_stale = blobmsg_get_bool(tb[CLIENTS_STALE]);
	}

	clients_prune(now);
	list = sorted_nodes(&count);
	if (list == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	blob_buf_init(&bb, 0);
	arr = blobmsg_open_array(&bb, "clients");
	for (i = 0; i < count; i++) {
		if (only_node != NULL && strcmp(only_node, list[i]->id) != 0) {
			continue;
		}
		avl_for_each_element(&clients, c, avl) {
			if (strcmp(c->node, list[i]->id) != 0) {
				continue;
			}
			if (!client_is_active(c) && !include_stale) {
				continue;
			}
			add_client(c, list[i], now, 1);
		}
	}
	blobmsg_close_array(&bb, arr);
	free(list);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

enum {
	BLOCK_NAME,
	BLOCK_DATA,
	BLOCK_TTL,
	__BLOCK_MAX,
};

static const struct blobmsg_policy add_block_policy[__BLOCK_MAX] = {
	[BLOCK_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[BLOCK_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	[BLOCK_TTL] = { .name = "ttl", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy remove_block_policy[1] = {
	[BLOCK_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_add_block(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			  const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__BLOCK_MAX];
	int ttl = 0;

	(void)ctx;
	(void)obj;
	(void)req;
	(void)method;

	blobmsg_parse(add_block_policy, __BLOCK_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[BLOCK_NAME] == NULL || tb[BLOCK_DATA] == NULL) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (tb[BLOCK_TTL] != NULL) {
		ttl = (int)blobmsg_get_u32(tb[BLOCK_TTL]);
	}
	return apmond_block_set(blobmsg_get_string(tb[BLOCK_NAME]), tb[BLOCK_DATA], ttl);
}

static int ubus_remove_block(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			     const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[1];

	(void)ctx;
	(void)obj;
	(void)req;
	(void)method;

	blobmsg_parse(remove_block_policy, 1, tb, blob_data(msg), blob_len(msg));
	if (tb[BLOCK_NAME] == NULL) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	return apmond_block_remove(blobmsg_get_string(tb[BLOCK_NAME]));
}

enum {
	FORGET_NODE,
	FORGET_CLIENT,
	FORGET_NODE_MAC,
	FORGET_CLIENT_MAC,
	__FORGET_MAX,
};

static const struct blobmsg_policy forget_policy[__FORGET_MAX] = {
	[FORGET_NODE] = { .name = "node", .type = BLOBMSG_TYPE_STRING },
	[FORGET_CLIENT] = { .name = "client", .type = BLOBMSG_TYPE_STRING },
	[FORGET_NODE_MAC] = { .name = "node_mac", .type = BLOBMSG_TYPE_STRING },
	[FORGET_CLIENT_MAC] = { .name = "client_mac", .type = BLOBMSG_TYPE_STRING },
};

/* forget {"node_mac"|"node": mac}: drop the node and its clients; forget {"client_mac"|"client": mac}: drop one client */
static int ubus_forget(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		       const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__FORGET_MAX];
	struct client *c;
	struct client *tmp;
	struct node *n;
	int removed = 0;

	(void)obj;
	(void)method;

	blobmsg_parse(forget_policy, __FORGET_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[FORGET_NODE] == NULL) {
		tb[FORGET_NODE] = tb[FORGET_NODE_MAC];
	}
	if (tb[FORGET_CLIENT] == NULL) {
		tb[FORGET_CLIENT] = tb[FORGET_CLIENT_MAC];
	}
	if (tb[FORGET_NODE] != NULL) {
		const char *id = blobmsg_get_string(tb[FORGET_NODE]);

		n = avl_find_element(&nodes, id, n, avl);
		if (n == NULL) {
			return UBUS_STATUS_NOT_FOUND;
		}
		avl_for_each_element_safe(&clients, c, avl, tmp) {
			if (strcmp(c->node, id) == 0) {
				client_delete(c);
				removed++;
			}
		}
		avl_delete(&nodes, &n->avl);
		free(n->report);
		free(n);
		LOG_NOTICE_("node %s forgotten with %d clients", id, removed);
	} else if (tb[FORGET_CLIENT] != NULL) {
		const char *mac = blobmsg_get_string(tb[FORGET_CLIENT]);

		c = avl_find_element(&clients, mac, c, avl);
		if (c == NULL) {
			return UBUS_STATUS_NOT_FOUND;
		}
		client_delete(c);
		removed = 1;
		LOG_NOTICE_("client %s forgotten", mac);
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "removed_clients", (uint32_t)removed);
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

void apmond_set_debuglevel(int level)
{
	int old = apmond.cfg.debuglevel;

	/* logged at notice level whichever way it goes, as 1.x */
	apmond.cfg.debuglevel = 1;
	LOG_NOTICE_("debuglevel changed from [ %d ] to [ %d ]", old, level);
	apmond.cfg.debuglevel = level;
}

enum {
	DEBUGLEVEL_LEVEL,
	__DEBUGLEVEL_MAX,
};

static const struct blobmsg_policy debuglevel_policy[__DEBUGLEVEL_MAX] = {
	[DEBUGLEVEL_LEVEL] = { .name = "level", .type = BLOBMSG_TYPE_INT32 },
};

/*
 * debuglevel {}: the current level; debuglevel {"level": N}: set it now and commit it to
 * option debuglevel in /etc/config/apmond, so it also survives a restart (as 1.x)
 */
static int ubus_debuglevel(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			   const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__DEBUGLEVEL_MAX];
	int persisted = 0;

	(void)obj;
	(void)method;

	blobmsg_parse(debuglevel_policy, __DEBUGLEVEL_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[DEBUGLEVEL_LEVEL] != NULL) {
		int level = (int)blobmsg_get_u32(tb[DEBUGLEVEL_LEVEL]);

		if (level < 0 || level > 3) {
			return UBUS_STATUS_INVALID_ARGUMENT;
		}
		if (level != apmond.cfg.debuglevel) {
			apmond_set_debuglevel(level);
		}
		if (apmond_config_write_debuglevel(level) == 0) {
			persisted = 1;
		} else {
			LOG_ERR_("could not commit option debuglevel to /etc/config/apmond");
		}
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "debuglevel", (uint32_t)apmond.cfg.debuglevel);
	if (tb[DEBUGLEVEL_LEVEL] != NULL) {
		blobmsg_add_u8(&bb, "persisted", (uint8_t)persisted);
	}
	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static const struct ubus_method apmond_methods[] = {
	UBUS_METHOD_NOARG("status", ubus_status),
	UBUS_METHOD_NOARG("nodes", ubus_nodes),
	UBUS_METHOD("node", ubus_node, node_policy),
	UBUS_METHOD("clients", ubus_clients, clients_policy),
	UBUS_METHOD("add_block", ubus_add_block, add_block_policy),
	UBUS_METHOD("remove_block", ubus_remove_block, remove_block_policy),
	UBUS_METHOD("forget", ubus_forget, forget_policy),
	UBUS_METHOD("debuglevel", ubus_debuglevel, debuglevel_policy),
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
