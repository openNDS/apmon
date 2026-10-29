/*
 * apmond 2.x - access point monitoring daemon (protocol: docs/PROTOCOL.md)
 *
 *   apmond          run the daemon (procd starts it in the foreground)
 *   apmond -c DIR   run with the uci config from DIR instead of /etc/config (testing)
 *   apmond bench    time the key derivation (PBKDF2 + HKDF) on this hardware
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "apmond.h"

struct apmond apmond;

static struct uloop_timeout seed_warn_timer;

void apmond_log(int level, const char *fmt, ...)
{
	static const int prio[] = { LOG_ERR, LOG_NOTICE, LOG_INFO, LOG_DEBUG };
	va_list ap;

	if (level > apmond.cfg.debuglevel && level > 0) {
		return;
	}
	va_start(ap, fmt);
	vsyslog(prio[level], fmt, ap);
	va_end(ap);
}

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

int main(int argc, char **argv)
{
	const char *confdir = NULL;
	uint64_t start;

	if (argc == 2 && strcmp(argv[1], "bench") == 0) {
		return bench();
	}
	if (argc == 3 && strcmp(argv[1], "-c") == 0) {
		confdir = argv[2];
	} else if (argc != 1) {
		fprintf(stderr, "usage: apmond [-c confdir] | apmond bench\n");
		return 1;
	}

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

	if (apmond_read_mac(apmond.cfg.device, apmond.id) != 0) {
		LOG_ERR_("cannot read the MAC address of device %s", apmond.cfg.device);
		return 1;
	}
	apmon_mac_format(apmond.id, apmond.id_str);

	start = apmon_monotonic_ms();
	if (apmon_derive_keys(apmond.cfg.seed, apmond.cfg.key_epoch, &apmond.keys) != 0) {
		LOG_ERR_("key derivation failed");
		return 1;
	}
	memset(apmond.cfg.seed, 0, sizeof(apmond.cfg.seed));
	LOG_INFO_("keys derived in %llu ms", (unsigned long long)(apmon_monotonic_ms() - start));

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

	LOG_NOTICE_("apmond %s started, node id %s, port %d", APMOND_VERSION, apmond.id_str, apmond.cfg.port);
	apmond_sender_start();

	uloop_run();

	ubus_free(apmond.ubus);
	uloop_done();
	return 0;
}
