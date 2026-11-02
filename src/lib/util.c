/*
 * libapmon helpers
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "apmon.h"

uint64_t apmon_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint64_t apmon_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

void apmon_hex_encode(const uint8_t *in, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[2 * i] = digits[in[i] >> 4];
		out[2 * i + 1] = digits[in[i] & 0x0f];
	}
	out[2 * len] = '\0';
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

int apmon_hex_decode(const char *in, uint8_t *out, size_t out_len)
{
	size_t i;

	if (strlen(in) != 2 * out_len) {
		return -1;
	}
	for (i = 0; i < out_len; i++) {
		int hi = hex_value(in[2 * i]);
		int lo = hex_value(in[2 * i + 1]);

		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

void apmon_mac_format(const uint8_t id[APMON_ID_LEN], char out[18])
{
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", id[0], id[1], id[2], id[3], id[4], id[5]);
}

int apmon_mac_parse(const char *s, uint8_t id[APMON_ID_LEN])
{
	unsigned int b[APMON_ID_LEN];
	int i;

	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != APMON_ID_LEN) {
		return -1;
	}
	for (i = 0; i < APMON_ID_LEN; i++) {
		id[i] = (uint8_t)b[i];
	}
	return 0;
}

/* r31: the sender line of "apmond status", always printed, zeros included (r33: errors too) */
void apmon_sender_summary(uint64_t sent, uint64_t failed, uint64_t time_sync_failed, uint32_t last_status,
			  const char *last_error, char *out, size_t len)
{
	if (last_error == NULL || last_error[0] == '\0') {
		last_error = "none";
	}
	snprintf(out, len, "reports sent %llu  failed %llu  time sync failed %llu  last HTTP status %u  last error %s\n"
		 "lost reports are counted on the collector: apmond node <id>",
		 (unsigned long long)sent, (unsigned long long)failed, (unsigned long long)time_sync_failed,
		 (unsigned int)last_status, last_error);
}

void apmon_exchange_error(int status, int have_reply, char *out, size_t len)
{
	if (status == 200 && have_reply) {
		snprintf(out, len, "%s", "");
		return;
	}
	if (status == 200) {
		snprintf(out, len, "bad reply");
		return;
	}
	if (status == 0) {
		snprintf(out, len, "no connection");
		return;
	}
	if (status == 401) {
		snprintf(out, len, "key rejected");
		return;
	}
	if (status == 409) {
		snprintf(out, len, "time or replay rejected");
		return;
	}
	snprintf(out, len, "HTTP %d", status);
}

int apmon_rate_limit_due(uint64_t now_ms, uint64_t *last_ms, uint64_t interval_ms)
{
	if (*last_ms != 0 && now_ms - *last_ms < interval_ms) {
		return 0;
	}
	*last_ms = now_ms;
	return 1;
}

/* r32, r34: which collector address a sender uses now (see apmon.h) */
enum apmon_collector_pick apmon_collector_pick(int have_ula, int ula_ready, int ipv4_fallback,
					       uint64_t waited_ms, int portal, int have_lan_gateway)
{
	if (portal) {
		if (!have_ula) {
			return APMON_PICK_IPV4;
		}
		if (ula_ready) {
			return APMON_PICK_ULA;
		}
		return APMON_PICK_WAIT;
	}
	if (ipv4_fallback && have_lan_gateway) {
		return APMON_PICK_IPV4;
	}
	if (!have_ula) {
		return APMON_PICK_IPV4;
	}
	if (ula_ready) {
		return APMON_PICK_ULA;
	}
	if (waited_ms < APMON_ULA_WAIT_MS) {
		return APMON_PICK_WAIT;
	}
	if (have_lan_gateway) {
		return APMON_PICK_IPV4;
	}
	return APMON_PICK_ULA;
}

/*
 * r32: a failed ULA send falls back to IPv4. A failed IPv4 send (in fallback, or because
 * the ULA was not ready in time) goes back to the ULA, never forcing a second IPv4 try.
 * r34: a portal candidate never falls back to IPv4.
 */
int apmon_fallback_after_failure(int failed_was_ula, int portal)
{
	if (portal) {
		return 0;
	}
	if (failed_was_ula) {
		return 1;
	}
	return 0;
}
