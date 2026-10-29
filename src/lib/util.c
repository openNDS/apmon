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
