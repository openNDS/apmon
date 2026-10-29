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

	if (apmond_read_mac(apmond.cfg.device, apmond.id) != 0) {
		LOG_ERR_("cannot read the MAC address of device %s", apmond.cfg.device);
		return 1;
	}
	apmon_mac_format(apmond.id, apmond.id_str);

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

	if (apmond.cfg.default_seed) {
		seed_warn_timer.cb = warn_default_seed;
		warn_default_seed(&seed_warn_timer);
	}

	LOG_NOTICE_("apmond %s started, node id %s, node ULA %s, port %d", APMOND_VERSION, apmond.id_str,
		    apmond.node_ula, apmond.cfg.port);
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
		if (argc == 4 && strcmp(argv[2], "-c") == 0) {
			return run_daemon(argv[3]);
		}
		if (argc == 2) {
			return run_daemon(NULL);
		}
		fprintf(stderr, "usage: apmond run [-c confdir]\n");
		return 1;
	}
	if (argc == 2 && strcmp(argv[1], "bench") == 0) {
		return bench();
	}
	return apmond_cli(argc, argv);
}
