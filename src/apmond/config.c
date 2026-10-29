/*
 * apmond uci configuration (/etc/config/apmond, section 'setup')
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "apmond.h"

/* Built-in passphrase so apmond works out of the box; flagged and warned about everywhere */
#define APMOND_DEFAULT_SEED "--__"

static const char *get_option(struct uci_context *ctx, struct uci_section *s, const char *name)
{
	if (s == NULL) {
		return NULL;
	}
	return uci_lookup_option_string(ctx, s, name);
}

static void get_string(struct uci_context *ctx, struct uci_section *s, const char *name,
		       char *out, size_t out_len, const char *def)
{
	const char *v = get_option(ctx, s, name);

	if (v == NULL || v[0] == '\0') {
		v = def;
	}
	strncpy(out, v, out_len - 1);
	out[out_len - 1] = '\0';
}

static int get_int(struct uci_context *ctx, struct uci_section *s, const char *name, int def, int min, int max)
{
	const char *v = get_option(ctx, s, name);
	char *end = NULL;
	long n;

	if (v == NULL || v[0] == '\0') {
		return def;
	}
	n = strtol(v, &end, 10);
	if (end == NULL || *end != '\0' || n < min || n > max) {
		LOG_ERR_("invalid value '%s' for option %s, using %d", v, name, def);
		return def;
	}
	return (int)n;
}

int apmond_config_load(struct apmond_config *cfg, const char *confdir)
{
	struct uci_context *ctx = uci_alloc_context();
	struct uci_package *pkg = NULL;
	struct uci_section *s = NULL;

	if (ctx == NULL) {
		return -1;
	}
	if (confdir != NULL) {
		uci_set_confdir(ctx, confdir);
	}

	if (uci_load(ctx, "apmond", &pkg) == UCI_OK) {
		s = uci_lookup_section(ctx, pkg, "setup");
	} else {
		LOG_NOTICE_("no /etc/config/apmond, using defaults");
	}

	cfg->enabled = get_int(ctx, s, "enabled", 1, 0, 1);
	get_string(ctx, s, "role", cfg->role, sizeof(cfg->role), "auto");
	get_string(ctx, s, "collector", cfg->collector, sizeof(cfg->collector), "");
	cfg->port = get_int(ctx, s, "port", APMON_DEFAULT_PORT, 1, 65535);
	cfg->interval = get_int(ctx, s, "interval", 30, 10, 3600);
	cfg->startup_delay = get_int(ctx, s, "startup_delay", 10, 0, 3600);
	get_string(ctx, s, "device", cfg->device, sizeof(cfg->device), "br-lan");
	get_string(ctx, s, "apmon_seed", cfg->seed, sizeof(cfg->seed), APMOND_DEFAULT_SEED);
	cfg->default_seed = strcmp(cfg->seed, APMOND_DEFAULT_SEED) == 0;
	cfg->key_epoch = (uint32_t)get_int(ctx, s, "key_epoch", 0, 0, 0x7fffffff);
	cfg->max_age = get_int(ctx, s, "max_age", 120, 10, 3600);
	cfg->client_stale_timeout = get_int(ctx, s, "client_stale_timeout", 600, 0, 86400);
	cfg->max_message_size = get_int(ctx, s, "max_message_size", APMON_DEFAULT_MAX_MESSAGE, 4096, 4194304);
	cfg->debuglevel = get_int(ctx, s, "debuglevel", 1, 0, 3);

	uci_free_context(ctx);
	return 0;
}
