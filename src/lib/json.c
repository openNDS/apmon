/*
 * libapmon minimal JSON writer (compact output, no dependencies)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

void apmon_json_init(struct apmon_json *j)
{
	memset(j, 0, sizeof(*j));
	j->need_comma = 0;
}

void apmon_json_free(struct apmon_json *j)
{
	free(j->buf);
	memset(j, 0, sizeof(*j));
}

static void append(struct apmon_json *j, const char *s, size_t n)
{
	if (j->failed) {
		return;
	}
	if (j->len + n + 1 > j->cap) {
		size_t cap = j->cap ? j->cap : 1024;
		char *nb;

		while (j->len + n + 1 > cap) {
			cap *= 2;
		}
		nb = realloc(j->buf, cap);
		if (nb == NULL) {
			j->failed = 1;
			return;
		}
		j->buf = nb;
		j->cap = cap;
	}
	memcpy(j->buf + j->len, s, n);
	j->len += n;
	j->buf[j->len] = '\0';
}

static void append_str(struct apmon_json *j, const char *s)
{
	append(j, s, strlen(s));
}

static void append_escaped(struct apmon_json *j, const char *s)
{
	append(j, "\"", 1);
	for (; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;
		char esc[8];

		if (c == '"' || c == '\\') {
			esc[0] = '\\';
			esc[1] = (char)c;
			append(j, esc, 2);
		} else if (c < 0x20) {
			snprintf(esc, sizeof(esc), "\\u%04x", c);
			append_str(j, esc);
		} else {
			append(j, (const char *)&c, 1);
		}
	}
	append(j, "\"", 1);
}

/* Comma and "key": prefix. key is NULL inside arrays. */
static void prefix(struct apmon_json *j, const char *key)
{
	if (j->need_comma) {
		append(j, ",", 1);
	}
	if (key != NULL) {
		append_escaped(j, key);
		append(j, ":", 1);
	}
	j->need_comma = 1;
}

void apmon_json_open_object(struct apmon_json *j, const char *key)
{
	prefix(j, key);
	append(j, "{", 1);
	j->need_comma = 0;
}

void apmon_json_close_object(struct apmon_json *j)
{
	append(j, "}", 1);
	j->need_comma = 1;
}

void apmon_json_open_array(struct apmon_json *j, const char *key)
{
	prefix(j, key);
	append(j, "[", 1);
	j->need_comma = 0;
}

void apmon_json_close_array(struct apmon_json *j)
{
	append(j, "]", 1);
	j->need_comma = 1;
}

void apmon_json_string(struct apmon_json *j, const char *key, const char *value)
{
	if (value == NULL) {
		apmon_json_null(j, key);
		return;
	}
	prefix(j, key);
	append_escaped(j, value);
}

void apmon_json_int(struct apmon_json *j, const char *key, int64_t value)
{
	char num[32];

	prefix(j, key);
	snprintf(num, sizeof(num), "%" PRId64, value);
	append_str(j, num);
}

void apmon_json_double(struct apmon_json *j, const char *key, double value)
{
	char num[32];

	if (!isfinite(value)) {
		apmon_json_null(j, key);
		return;
	}
	prefix(j, key);
	snprintf(num, sizeof(num), "%.2f", value);
	append_str(j, num);
}

void apmon_json_bool(struct apmon_json *j, const char *key, int value)
{
	prefix(j, key);
	if (value) {
		append_str(j, "true");
	} else {
		append_str(j, "false");
	}
}

void apmon_json_null(struct apmon_json *j, const char *key)
{
	prefix(j, key);
	append_str(j, "null");
}
