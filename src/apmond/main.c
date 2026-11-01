/*
 * apmond 2.x - access point monitoring daemon (protocol: docs/PROTOCOL.md)
 *
 *   apmond run [-c DIR]   run the daemon (procd starts it in the foreground);
 *                         -c reads the uci config from DIR instead of /etc/config (testing)
 *   apmond bench          time the key derivation (PBKDF2 + HKDF) on this hardware
 *   apmond <command>      command line interface, see cli.c (apmond help)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "apmond.h"

struct apmond apmond;

static struct uloop_timeout seed_warn_timer;

static void warn_default_seed(struct uloop_timeout *t)
{
	LOG_NOTICE_("The built-in default passphrase is in use. Make apmond more secure: on every node "
		    "uci set apmond.setup.apmon_seed='<your passphrase>'; uci commit apmond; service apmond restart");
	uloop_timeout_set(t, 6 * 3600 * 1000);
}

static int bench(void)
{
	struct apmon_keys keys;
	uint64_t start = apmon_monotonic_ms();
	uint64_t ms;

	if (apmon_derive_keys("benchmark passphrase", 0, &keys) != 0) {
		printf("key derivation failed\n");
		return 1;
	}
	ms = apmon_monotonic_ms() - start;
	printf("PBKDF2-HMAC-SHA256 x %d + HKDF: %llu ms\n", APMON_PBKDF2_ITERATIONS, (unsigned long long)ms);
	return 0;
}

/*
 * The layer 3 device we work on (ULA addresses, listener, uplink test).
 * option netdev wins, else the l3_device of option interface (default lan),
 * else option device. On a VLAN setup this is eg br-lan.10, not br-lan.
 */
static void resolve_netdev(void)
{
	char object[64];
	struct blob_attr *out;
	struct blob_attr *cur;
	size_t rem;

	if (apmond.cfg.netdev[0] != '\0') {
		LOG_INFO_("network device [ %s ] from option netdev", apmond.cfg.netdev);
		return;
	}
	snprintf(apmond.cfg.netdev, sizeof(apmond.cfg.netdev), "%s", apmond.cfg.device);
	snprintf(object, sizeof(object), "network.interface.%s", apmond.cfg.interface);
	if (apmond_ubus_call(apmond.ubus, object, "status", NULL, &out) != 0) {
		LOG_NOTICE_("interface [ %s ] not found, using device [ %s ]", apmond.cfg.interface, apmond.cfg.netdev);
		return;
	}
	blob_for_each_attr(cur, out, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING) {
			continue;
		}
		if (strcmp(blobmsg_name(cur), "l3_device") != 0) {
			continue;
		}
		snprintf(apmond.cfg.netdev, sizeof(apmond.cfg.netdev), "%s", blobmsg_get_string(cur));
	}
	free(out);
	LOG_NOTICE_("interface [ %s ] is on network device [ %s ]", apmond.cfg.interface, apmond.cfg.netdev);
}

/*
 * The WAN device from netifd: ubus network.interface.wan status "device", else "l3_device".
 * Not libuci: /etc/config/network is root only (0600) and apmond runs as user apmond.
 * No WAN interface (a dumb AP) or no ubus: empty, and the chain skips that step.
 */
static void wan_device(char *out, size_t len)
{
	enum {
		WAN_DEVICE,
		WAN_L3_DEVICE,
		__WAN_MAX
	};
	static const struct blobmsg_policy policy[__WAN_MAX] = {
		[WAN_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
		[WAN_L3_DEVICE] = { .name = "l3_device", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__WAN_MAX];
	struct blob_attr *reply = NULL;
	struct ubus_context *ctx;
	struct blob_buf b;

	out[0] = '\0';
	ctx = ubus_connect(NULL);
	if (ctx == NULL) {
		LOG_INFO_("no ubus, node id without the WAN device");
		return;
	}
	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	if (apmond_ubus_call(ctx, "network.interface.wan", "status", b.head, &reply) == 0) {
		blobmsg_parse(policy, __WAN_MAX, tb, blob_data(reply), blob_len(reply));
		if (tb[WAN_DEVICE] != NULL) {
			snprintf(out, len, "%s", blobmsg_get_string(tb[WAN_DEVICE]));
		} else if (tb[WAN_L3_DEVICE] != NULL) {
			snprintf(out, len, "%s", blobmsg_get_string(tb[WAN_L3_DEVICE]));
		}
	}
	free(reply);
	blob_buf_free(&b);
	ubus_free(ctx);
}

/*
 * Node id = factory (label) MAC, from the libapmon chain mesh11sd 8.0.0 shares
 * (src/lib/factory_mac.c), so both agree on the id. No br-lan fallback: refuse to run.
 */
static int read_node_id(void)
{
	char wan[64];
	char source[96];

	wan_device(wan, sizeof(wan));
	if (apmon_factory_mac("", wan, apmond.id, source, sizeof(source)) != 0) {
		LOG_ERR_("cannot determine the factory MAC address (no label MAC, no universally administered permanent ethernet MAC)");
		return -1;
	}
	apmon_mac_format(apmond.id, apmond.id_str);
	LOG_NOTICE_("node id %s (factory MAC from %s)", apmond.id_str, source);
	return 0;
}

static int run_daemon(const char *confdir)
{
	uint64_t start;

	openlog("apmond", LOG_PID, LOG_DAEMON);
	apmond.cfg.debuglevel = 1;

	if (apmond_config_load(&apmond.cfg, confdir) != 0) {
		LOG_ERR_("could not read configuration");
		return 1;
	}
	if (!apmond.cfg.enabled) {
		LOG_NOTICE_("disabled in /etc/config/apmond");
		return 0;
	}

	apmond_log_init();

	if (read_node_id() != 0) {
		return 1;
	}

	start = apmon_monotonic_ms();
	apmond.start_mono_ms = start;
	if (apmon_derive_keys_with_previous(apmond.cfg.seed, apmond.cfg.key_epoch, &apmond.keys,
					    &apmond.prev_keys) != 0) {
		LOG_ERR_("key derivation failed");
		return 1;
	}
	LOG_INFO_("keys derived in %llu ms", (unsigned long long)(apmon_monotonic_ms() - start));

	if (apmond_ula_init(apmond.cfg.seed) != 0) {
		LOG_ERR_("could not derive the ULA prefix");
	}
	memset(apmond.cfg.seed, 0, sizeof(apmond.cfg.seed));

	apmon_random(&apmond.seq, sizeof(apmond.seq));

	uloop_init();

	apmond.ubus = ubus_connect(NULL);
	if (apmond.ubus == NULL) {
		LOG_ERR_("cannot connect to ubus");
		return 1;
	}
	ubus_add_uloop(apmond.ubus);
	apmond_ubus_init();
	resolve_netdev();

	if (apmond.cfg.default_seed) {
		seed_warn_timer.cb = warn_default_seed;
		warn_default_seed(&seed_warn_timer);
	}

	apmond_identity_init();
	LOG_NOTICE_("apmond %s started, node id %s, node ULA %s, port %d", APMOND_VERSION, apmond.id_str,
		    apmond.node_ula, apmond.cfg.port);
	LOG_INFO_("build %s %s, sha256 %s", APMOND_PACKAGE_VERSION, APMOND_BUILD_COMMIT,
		  apmond.running_sha256[0] != '\0' ? apmond.running_sha256 : "unknown");
	apmond_sender_start();

	uloop_run();

	/* SIGTERM from procd (service apmond stop): remove our addresses */
	apmond_collector_stop();
	apmond_ula_cleanup();
	LOG_NOTICE_("apmond stopped");

	ubus_free(apmond.ubus);
	uloop_done();
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "run") == 0) {
		const char *confdir = NULL;
		const char *user = NULL;
		int i;

		for (i = 2; i + 1 < argc; i += 2) {
			if (strcmp(argv[i], "-c") == 0) {
				confdir = argv[i + 1];
			} else if (strcmp(argv[i], "-u") == 0) {
				user = argv[i + 1];
			} else {
				break;
			}
		}
		if (i != argc) {
			fprintf(stderr, "usage: apmond run [-c confdir] [-u user]\n");
			return 1;
		}
		if (user != NULL && apmond_drop_privileges(user) != 0) {
			return 1;
		}
		return run_daemon(confdir);
	}
	if (argc == 2 && strcmp(argv[1], "bench") == 0) {
		return bench();
	}
	return apmond_cli(argc, argv);
}
