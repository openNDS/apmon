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

#include <uci.h>

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

/* uci network.wan.device, as 1.x "uci -q get network.wan.device" */
static void wan_device(char *out, size_t len)
{
	struct uci_context *ctx = uci_alloc_context();
	struct uci_ptr ptr;
	char spec[] = "network.wan.device";

	out[0] = '\0';
	if (ctx == NULL) {
		return;
	}
	if (uci_lookup_ptr(ctx, &ptr, spec, true) == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && ptr.o != NULL && ptr.o->type == UCI_TYPE_STRING) {
			snprintf(out, len, "%s", ptr.o->v.string);
		}
	}
	uci_free_context(ctx);
}

/*
 * Node id = factory (label) MAC, as apmond 1.x and mesh11sd (which identifies its peers by it).
 * Not the MAC of br-lan: mesh11sd rewrites that. Falls back to option device.
 */
static int read_node_id(void)
{
	char wan[64];
	char source[96];

	wan_device(wan, sizeof(wan));
	if (apmon_factory_mac("", wan, apmond.cfg.device, apmond.id, source, sizeof(source)) != 0) {
		LOG_ERR_("cannot determine the factory MAC address (no label MAC, no %s)", apmond.cfg.device);
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
