/*
 * apmond sender: time sync with the collector, then one encrypted REPORT per interval
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg_json.h>

#include "apmond.h"

#define RESYNC_INTERVAL_MS (6ULL * 3600 * 1000)
#define HTTP_TIMEOUT_S 5

static struct uloop_timeout report_timer;

/* Time on the collector-referenced clock (docs/PROTOCOL.md section 5) */
uint64_t apmond_sender_time(void)
{
	return (uint64_t)((int64_t)apmon_monotonic_ms() + apmond.clock_offset_ms);
}

/*
 * Collector candidate: role 'collector', or role 'auto' and the default route does not go through
 * option device (this node has the upstream gateway).
 */
static int collector_candidate(void)
{
	char ifname[32];
	char gateway[64];

	if (strcmp(apmond.cfg.role, "collector") == 0) {
		return 1;
	}
	if (strcmp(apmond.cfg.role, "sender") == 0) {
		return 0;
	}
	if (apmond_default_route(ifname, sizeof(ifname), gateway, sizeof(gateway)) != 0) {
		return 0;
	}
	if (strcmp(ifname, apmond.cfg.netdev) == 0) {
		return 0;
	}
	return 1;
}

/*
 * Sender target: option collector if set, else the collector ULA <prefix>:<subnet>::1,
 * falling back to the default gateway's IPv4 address after a failed attempt (and back again).
 */
/* For log messages: the collector's own reports never leave the node */
static const char *collector_name(void)
{
	if (apmond.role == ROLE_COLLECTOR) {
		return "local";
	}
	if (apmond.collector_addr[0] == '\0') {
		return "(none)";
	}
	return apmond.collector_addr;
}

static void choose_collector_address(void)
{
	char ifname[32];
	char gateway[64];

	if (apmond.cfg.collector[0] != '\0') {
		snprintf(apmond.collector_addr, sizeof(apmond.collector_addr), "%s", apmond.cfg.collector);
		snprintf(apmond.collector_via, sizeof(apmond.collector_via), "config");
		return;
	}

	/* Until our own ULA has passed DAD it cannot be a source address: use IPv4 meanwhile */
	if (!apmond.ipv4_fallback && apmond.router_ula[0] != '\0' && apmond_ula_node_ready()) {
		snprintf(apmond.collector_addr, sizeof(apmond.collector_addr), "%s", apmond.router_ula);
		snprintf(apmond.collector_via, sizeof(apmond.collector_via), "ula");
		return;
	}

	if (apmond_default_route(ifname, sizeof(ifname), gateway, sizeof(gateway)) == 0) {
		snprintf(apmond.collector_addr, sizeof(apmond.collector_addr), "%s", gateway);
		snprintf(apmond.collector_via, sizeof(apmond.collector_via), "ipv4");
		return;
	}

	snprintf(apmond.collector_addr, sizeof(apmond.collector_addr), "%s", apmond.router_ula);
	snprintf(apmond.collector_via, sizeof(apmond.collector_via), "ula");
}

static void decide_role(void)
{
	enum apmond_role role;
	int holding;

	holding = apmond_ula_tick(collector_candidate());

	if (holding) {
		role = ROLE_COLLECTOR;
	} else {
		role = ROLE_SENDER;
		choose_collector_address();
	}

	if (role != apmond.role) {
		apmond.role = role;
		apmond.time_synced = 0;
		if (role == ROLE_COLLECTOR) {
			LOG_NOTICE_("role: collector");
		} else {
			LOG_NOTICE_("role: sender, collector %s port %d", apmond.collector_addr, apmond.cfg.port);
		}
	}

	if (role == ROLE_COLLECTOR && !apmond_collector_running()) {
		apmond_collector_start();
	}
	if (role != ROLE_COLLECTOR && apmond_collector_running()) {
		apmond_collector_stop();
	}
}

static uint16_t header_flags(void)
{
	uint16_t flags = 0;

	if (apmond.time_synced) {
		flags |= APMON_FLAG_CLOCK_FROM_COLLECTOR;
	}
	if (apmond.cfg.default_seed) {
		flags |= APMON_FLAG_DEFAULT_PASSPHRASE;
	}
	return flags;
}

/*
 * Seal and send one message, then open and check the collector's reply.
 * Returns the HTTP status (0 on transport failure). *reply is the reply's JSON (malloc'd) when present and valid.
 */
static int exchange(uint8_t type, const char *plaintext, char **reply)
{
	struct apmon_header h;
	struct apmon_header rh;
	uint8_t *msg = NULL;
	uint8_t *resp = NULL;
	size_t msg_len = 0;
	size_t resp_len = 0;
	char *pt = NULL;
	char nonce_hex[2 * APMON_NONCE_LEN + 1];
	const char *path = APMON_PATH_REPORT;
	int status = 0;

	*reply = NULL;

	memset(&h, 0, sizeof(h));
	h.type = type;
	h.flags = header_flags();
	h.key_epoch = apmond.keys.epoch;
	memcpy(h.sender_id, apmond.id, APMON_ID_LEN);
	h.timestamp_ms = apmond_sender_time();
	h.seq = apmond.seq;
	apmond.seq++;

	if (apmon_seal(apmond.keys.s2c, &h, plaintext, strlen(plaintext), &msg, &msg_len) != APMON_OK) {
		LOG_ERR_("could not seal message");
		return 0;
	}
	apmon_hex_encode(h.nonce, APMON_NONCE_LEN, nonce_hex);

	if (type == APMON_TYPE_TIME_REQ) {
		path = APMON_PATH_TIME;
	}

	if (apmond.role == ROLE_COLLECTOR) {
		/* Our own report: same processing as a network report, without the loopback round trip */
		status = apmond_collector_process(type == APMON_TYPE_TIME_REQ, msg, msg_len, "local", &resp, &resp_len);
	} else if (apmond_http_post(apmond.collector_addr, apmond.cfg.port, path, msg, msg_len, HTTP_TIMEOUT_S,
				    &status, &resp, &resp_len) != 0) {
		LOG_INFO_("collector %s port %d not reachable", apmond.collector_addr, apmond.cfg.port);
		status = 0;
		/* try the other address (ULA <-> IPv4 gateway) next time */
		if (apmond.ipv4_fallback) {
			apmond.ipv4_fallback = 0;
		} else {
			apmond.ipv4_fallback = 1;
		}
	}
	free(msg);

	if (resp != NULL && resp_len > 0) {
		if (apmon_open(apmond.keys.c2s, resp, resp_len, &rh, &pt, NULL) == APMON_OK &&
		    strstr(pt, nonce_hex) != NULL) {
			*reply = pt;
		} else {
			LOG_INFO_("ignoring a reply that failed authentication or does not answer our request");
			free(pt);
		}
	}
	free(resp);
	return status;
}

static int reply_collector_time(const char *reply, uint64_t *t, char *echo, size_t echo_len)
{
	static const struct blobmsg_policy policy[] = {
		{ .name = "collector_time", .type = BLOBMSG_TYPE_UNSPEC },
		{ .name = "echo_nonce", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[2];
	struct blob_buf b;
	int ret = -1;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_string(&b, reply)) {
		blob_buf_free(&b);
		return -1;
	}
	blobmsg_parse(policy, 2, tb, blob_data(b.head), blob_len(b.head));

	if (tb[0] != NULL && tb[1] != NULL) {
		if (blobmsg_type(tb[0]) == BLOBMSG_TYPE_INT64) {
			*t = blobmsg_get_u64(tb[0]);
			ret = 0;
		} else if (blobmsg_type(tb[0]) == BLOBMSG_TYPE_DOUBLE) {
			*t = (uint64_t)blobmsg_get_double(tb[0]);
			ret = 0;
		}
		snprintf(echo, echo_len, "%s", blobmsg_get_string(tb[1]));
	}

	blob_buf_free(&b);
	return ret;
}

static void set_clock(uint64_t collector_time)
{
	apmond.clock_offset_ms = (int64_t)collector_time - (int64_t)apmon_monotonic_ms();
}

static int time_sync(void)
{
	char *reply = NULL;
	char echo[2 * APMON_NONCE_LEN + 1];
	uint64_t t = 0;
	int status;

	status = exchange(APMON_TYPE_TIME_REQ, "{\"v\":2,\"type\":\"time_req\"}", &reply);
	if (status == 200 && reply != NULL && reply_collector_time(reply, &t, echo, sizeof(echo)) == 0) {
		set_clock(t);
		apmond.time_synced = 1;
		apmond.last_sync_mono_ms = apmon_monotonic_ms();
		LOG_INFO_("clock synchronised with collector");
		free(reply);
		return 0;
	}

	if (status == 401) {
		LOG_NOTICE_("collector rejected our key: check apmon_seed and key_epoch are the same on every node");
	}
	free(reply);
	return -1;
}

static int send_report(void)
{
	char *report;
	char *reply = NULL;
	char echo[2 * APMON_NONCE_LEN + 1];
	uint64_t t = 0;
	int status;

	report = apmond_build_report(&apmond, apmond_sender_time());
	if (report == NULL) {
		LOG_ERR_("could not build report");
		return 0;
	}

	status = exchange(APMON_TYPE_REPORT, report, &reply);
	free(report);

	if (reply != NULL && reply_collector_time(reply, &t, echo, sizeof(echo)) == 0) {
		/* Every ACK/ERROR carries collector_time: track drift */
		set_clock(t);
	}
	free(reply);
	return status;
}

static int ipv4_successes;

static void report_cb(struct uloop_timeout *t)
{
	int status;
	static int uci_level = -1;
	int level = apmond_config_read_debuglevel();

	/*
	 * As 1.x: a debuglevel changed in uci applies on the next cycle. Only a change in uci
	 * counts, so a level set over ubus that could not be saved (jailed) is not undone here.
	 */
	if (level >= 0 && level != uci_level) {
		uci_level = level;
		if (level != apmond.cfg.debuglevel) {
			apmond_set_debuglevel(level);
		}
	}

	decide_role();

	if (apmond.role == ROLE_COLLECTOR) {
		apmond_collector_housekeeping();
	}

	if (apmond.role != ROLE_UNKNOWN) {
		int need_sync = !apmond.time_synced;

		if (apmon_monotonic_ms() - apmond.last_sync_mono_ms > RESYNC_INTERVAL_MS) {
			need_sync = 1;
		}
		if (need_sync) {
			time_sync();
		}

		if (apmond.time_synced) {
			status = send_report();
			if (status == 409) {
				/* time or replay: resync once and resend with a new nonce */
				apmond.time_synced = 0;
				if (time_sync() == 0) {
					status = send_report();
				}
			}

			apmond.last_status = status;
			if (status == 200 && apmond.ipv4_fallback) {
				/* working over IPv4: try the ULA again every 10 reports */
				ipv4_successes++;
				if (ipv4_successes >= 10) {
					ipv4_successes = 0;
					apmond.ipv4_fallback = 0;
				}
			}

			if (status == 200) {
				apmond.reports_sent++;
				apmond.last_ack_ms = apmond_sender_time();
				LOG_DEBUG_("report %u accepted by collector %s", (unsigned int)(apmond.seq - 1),
					   collector_name());
			} else {
				apmond.reports_failed++;
				LOG_INFO_("report not accepted (HTTP %d)", status);
			}
		}
	}

	uloop_timeout_set(t, apmond.cfg.interval * 1000);
}

void apmond_sender_start(void)
{
	report_timer.cb = report_cb;
	uloop_timeout_set(&report_timer, apmond.cfg.startup_delay * 1000);
}
