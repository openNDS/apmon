/*
 * libapmon helpers that need no OpenWrt libraries (unit tested on the host):
 * ULA derivation (as apmond 1.x), extension block validation, age formatting, aligned text tables
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

/* ---------- ULA (same derivation as apmond 1.x and mesh11sd) ---------- */

/*
 * hash = sha256(passphrase) as 64 hex characters
 * id = hash characters 9..38 (1.x: tail -c55 | head -c30)
 * prefix = fd<id[9..10]>:<id[11..14]>:<id[15..18]>, subnet = id[19..22]
 * out: the first 8 bytes (the /64) of the ULA network
 */
int apmon_ula_prefix(const char *passphrase, uint8_t out[8])
{
	uint8_t digest[32];
	char hex[65];
	const char *id;
	char text[17];

	if (apmon_sha256((const uint8_t *)passphrase, strlen(passphrase), digest) != 0) {
		return -1;
	}
	apmon_hex_encode(digest, sizeof(digest), hex);
	id = hex + 9;

	/* fd + 2 + 4 + 4 + 4 hex digits = 16 hex digits = 8 bytes */
	memcpy(text, "fd", 2);
	memcpy(text + 2, id + 9, 2);
	memcpy(text + 4, id + 11, 4);
	memcpy(text + 8, id + 15, 4);
	memcpy(text + 12, id + 19, 4);
	text[16] = '\0';

	return apmon_hex_decode(text, out, 8);
}

/* Modified EUI-64 interface id from a MAC (RFC 4291 appendix A) */
void apmon_eui64_iid(const uint8_t mac[APMON_ID_LEN], uint8_t out[8])
{
	out[0] = mac[0] ^ 0x02;
	out[1] = mac[1];
	out[2] = mac[2];
	out[3] = 0xff;
	out[4] = 0xfe;
	out[5] = mac[3];
	out[6] = mac[4];
	out[7] = mac[5];
}

/* ---------- extension blocks ---------- */

int apmon_block_name_valid(const char *name)
{
	size_t len;
	size_t i;

	if (name == NULL) {
		return 0;
	}
	len = strlen(name);
	if (len == 0 || len > APMON_BLOCK_NAME_MAX) {
		return 0;
	}
	for (i = 0; i < len; i++) {
		char c = name[i];
		int ok = 0;

		if (c >= 'a' && c <= 'z') {
			ok = 1;
		} else if (c >= '0' && c <= '9') {
			ok = 1;
		} else if (c == '_' || c == '-') {
			ok = 1;
		}
		if (!ok) {
			return 0;
		}
	}
	return 1;
}

/* ---------- formatting ---------- */

void apmon_format_age(int64_t seconds, char *out, size_t out_len)
{
	if (seconds < 0) {
		snprintf(out, out_len, "-");
	} else if (seconds < 60) {
		snprintf(out, out_len, "%llds", (long long)seconds);
	} else if (seconds < 3600) {
		snprintf(out, out_len, "%lldm", (long long)(seconds / 60));
	} else if (seconds < 86400) {
		snprintf(out, out_len, "%lldh", (long long)(seconds / 3600));
	} else {
		snprintf(out, out_len, "%lldd", (long long)(seconds / 86400));
	}
}

void apmon_table_init(struct apmon_table *t, int columns)
{
	memset(t, 0, sizeof(*t));
	t->columns = columns;
}

void apmon_table_add(struct apmon_table *t, const char *cell)
{
	char **cells;
	size_t need = t->count + 1;

	if (need > t->cap) {
		size_t cap = t->cap ? t->cap * 2 : 64;

		cells = realloc(t->cells, cap * sizeof(*cells));
		if (cells == NULL) {
			return;
		}
		t->cells = cells;
		t->cap = cap;
	}
	if (cell == NULL) {
		cell = "-";
	}
	t->cells[t->count] = strdup(cell);
	t->count++;
}

/* Write the table with columns padded to their widest cell, separated by two spaces */
size_t apmon_table_render(const struct apmon_table *t, char *out, size_t out_len)
{
	size_t widths[APMON_TABLE_MAX_COLUMNS] = { 0 };
	size_t pos = 0;
	size_t i;

	if (t->columns <= 0 || t->columns > APMON_TABLE_MAX_COLUMNS) {
		return 0;
	}

	for (i = 0; i < t->count; i++) {
		size_t len = strlen(t->cells[i]);
		size_t col = i % (size_t)t->columns;

		if (len > widths[col]) {
			widths[col] = len;
		}
	}

	for (i = 0; i < t->count; i++) {
		size_t col = i % (size_t)t->columns;
		int last = col == (size_t)t->columns - 1;
		int n;

		if (last) {
			n = snprintf(out + pos, out_len > pos ? out_len - pos : 0, "%s\n", t->cells[i]);
		} else {
			n = snprintf(out + pos, out_len > pos ? out_len - pos : 0, "%-*s  ", (int)widths[col],
				     t->cells[i]);
		}
		if (n > 0) {
			pos += (size_t)n;
		}
	}
	return pos;
}

void apmon_table_free(struct apmon_table *t)
{
	size_t i;

	for (i = 0; i < t->count; i++) {
		free(t->cells[i]);
	}
	free(t->cells);
	memset(t, 0, sizeof(*t));
}
