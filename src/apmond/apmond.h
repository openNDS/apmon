/*
 * apmond 2.x daemon - shared declarations
 * SPDX-License-Identifier: GPL-2.0-only
 */
#pragma once

#include <stdint.h>
#include <syslog.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "apmon.h"

#define APMOND_VERSION "2.0.0beta"

/* Baked in at build time (CMake -D, from the OpenWrt Makefile); see CMakeLists.txt */
#ifndef APMOND_PACKAGE_VERSION
#define APMOND_PACKAGE_VERSION "dev"
#endif
#ifndef APMOND_BUILD_COMMIT
#define APMOND_BUILD_COMMIT "unknown"
#endif
#define APMOND_INSTALL_PATH "/usr/sbin/apmond"
#define APMOND_CONFIG_PATH "/etc/config/apmond"

struct apmond_config {
	int enabled;
	char role[16];             /* auto | collector | sender */
	char collector[64];        /* sender: collector address, empty = default gateway */
	int port;
	int interval;
	int startup_delay;
	char device[32];
	char interface[32];
	char netdev[32];
	char seed[256];
	int default_seed;
	uint32_t key_epoch;
	int max_age;
	int client_stale_timeout;
	int max_message_size;
	int debuglevel;
	char log_mountpoint[128];
	int max_log_entries;
	int prev_epoch_grace;
	int router_takeover_misses;
	int claim_delay_max;
};

enum apmond_role {
	ROLE_UNKNOWN = 0,
	ROLE_COLLECTOR,
	ROLE_SENDER,
};

struct apmond {
	struct apmond_config cfg;
	struct apmon_keys keys;
	struct apmon_keys prev_keys;     /* key_epoch - 1, accepted for prev_epoch_grace s after start */
	uint64_t start_mono_ms;
	uint8_t id[APMON_ID_LEN];
	char id_str[18];
	enum apmond_role role;
	char collector_addr[64];
	char collector_via[8];          /* "ula", "ipv4" or "config" */
	int ipv4_fallback;
	char node_ula[46];
	char router_ula[46];
	char role_reason[160];
	struct ubus_context *ubus;

	/* sender state */
	uint32_t seq;
	int time_synced;
	int64_t clock_offset_ms;        /* collector time - our monotonic clock */
	uint64_t last_sync_mono_ms;
	uint64_t last_ack_ms;
	int last_status;
	uint64_t reports_sent;
	uint64_t reports_failed;

	/* identity of the code (identity.c): empty hash = unknown */
	char running_sha256[65];
	char installed_sha256[65];
};

extern struct apmond apmond;

/* logging, main.c */
void apmond_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define LOG_ERR_(...) apmond_log(0, __VA_ARGS__)
#define LOG_NOTICE_(...) apmond_log(1, __VA_ARGS__)
#define LOG_INFO_(...) apmond_log(2, __VA_ARGS__)
#define LOG_DEBUG_(...) apmond_log(3, __VA_ARGS__)

/* log.c */
int apmond_log_path(const struct apmond_config *cfg, char *path, size_t path_len, char *reason, size_t reason_len,
		    int create);
void apmond_log_init(void);
int apmond_read_log(int follow);

/* ula.c */
int apmond_ula_init(const char *passphrase);
int apmond_ula_tick(int candidate);
int apmond_ula_holding_router(void);
int apmond_ula_node_ready(void);

/* vlan.c */
int apmond_port_vlan(const char *port, uint64_t now_ms);
int apmond_port_vxlan(const char *port, uint64_t now_ms, uint32_t *vni, char *device, size_t device_len);
void apmond_ula_cleanup(void);

/* blocks.c - extension blocks carried in this node's reports */
int apmond_block_set(const char *name, struct blob_attr *data, int ttl);
int apmond_block_remove(const char *name);
void apmond_blocks_json(struct apmon_json *j);
void apmond_blocks_list(struct blob_buf *b);

/* cli.c */
int apmond_cli(int argc, char **argv);

/* config.c */
int apmond_config_load(struct apmond_config *cfg, const char *confdir);
int apmond_config_read_debuglevel(void);
int apmond_config_write_debuglevel(int level);
void apmond_set_debuglevel(int level);

/* collect.c - build the REPORT plaintext */
char *apmond_build_report(struct apmond *a, uint64_t now_ms);
int apmond_read_mac(const char *ifname, uint8_t id[APMON_ID_LEN]);
int apmond_default_route(char *ifname, size_t ifname_len, char *gateway, size_t gw_len);
int apmond_ubus_call(struct ubus_context *ctx, const char *object, const char *method,
		     struct blob_attr *msg, struct blob_attr **out);

/* sender.c */
void apmond_sender_start(void);
uint64_t apmond_sender_time(void);

/* collector.c */
int apmond_collector_start(void);
int apmond_collector_running(void);
int apmond_collector_process(int is_time, const uint8_t *body, size_t len, const char *source,
			     uint8_t **resp, size_t *resp_len);
void apmond_ubus_init(void);
void apmond_collector_stop(void);
void apmond_collector_housekeeping(void);

/* http_client.c */
int apmond_http_post(const char *host, int port, const char *path, const uint8_t *body, size_t len,
		     int timeout_s, int *status, uint8_t **resp, size_t *resp_len);

/* identity.c: sha256 of the running and the installed binary */
void apmond_identity_init(void);
void apmond_identity_refresh(void);
int apmond_restart_needed(void);

/* config.c: give group apmond read access again after a root uci commit */
void apmond_config_share_with_daemon(void);

/* privdrop.c: become user, keeping CAP_NET_ADMIN only (when ujail is not available) */
int apmond_drop_privileges(const char *user);
