/*
 * Pretty JSON writer for the apmond CLI, in the style of jq and apmond 1.x:
 * two space indent, "key": value, one element per line, {} and [] when empty.
 * The caller walks its data (a blobmsg reply) and calls these in document order.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

static void put(struct apmon_pretty *p, const char *s, size_t n)
{
	char *grown;
	size_t cap;

	if (p->failed) {
		return;
	}
	if (p->len + n + 1 > p->cap) {
		cap = p->cap * 2 + n + 256;
		grown = realloc(p->buf, cap);
		if (grown == NULL) {
			p->failed = 1;
			return;
		}
		p->buf = grown;
		p->cap = cap;
	}
	memcpy(p->buf + p->len, s, n);
	p->len += n;
	p->buf[p->len] = '\0';
}

static void puts_(struct apmon_pretty *p, const char *s)
{
	put(p, s, strlen(s));
}

static void indent(struct apmon_pretty *p)
{
	int i;

	for (i = 0; i < p->depth; i++) {
		put(p, "  ", 2);
	}
}

static void put_string(struct apmon_pretty *p, const char *s)
{
	char esc[8];

	put(p, "\"", 1);
	for (; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"') {
			puts_(p, "\\\"");
		} else if (c == '\\') {
			puts_(p, "\\\\");
		} else if (c == '\n') {
			puts_(p, "\\n");
		} else if (c == '\r') {
			puts_(p, "\\r");
		} else if (c == '\t') {
			puts_(p, "\\t");
		} else if (c < 0x20) {
			snprintf(esc, sizeof(esc), "\\u%04x", c);
			puts_(p, esc);
		} else {
			put(p, (const char *)&c, 1);
		}
	}
	put(p, "\"", 1);
}

/* Start a new element: comma after the previous one, newline, indent, "key": inside objects */
static void element(struct apmon_pretty *p, const char *key)
{
	if (p->depth == 0) {
		return;
	}
	if (p->count[p->depth] > 0) {
		put(p, ",", 1);
	}
	put(p, "\n", 1);
	p->count[p->depth]++;
	indent(p);
	if (p->is_object[p->depth]) {
		if (key == NULL) {
			key = "";
		}
		put_string(p, key);
		put(p, ": ", 2);
	}
}

void apmon_pretty_init(struct apmon_pretty *p)
{
	memset(p, 0, sizeof(*p));
}

void apmon_pretty_free(struct apmon_pretty *p)
{
	free(p->buf);
	memset(p, 0, sizeof(*p));
}

static void open_container(struct apmon_pretty *p, const char *key, int is_object)
{
	element(p, key);
	if (is_object) {
		put(p, "{", 1);
	} else {
		put(p, "[", 1);
	}
	if (p->depth + 1 >= APMON_PRETTY_DEPTH) {
		p->failed = 1;
		return;
	}
	p->depth++;
	p->count[p->depth] = 0;
	p->is_object[p->depth] = is_object;
}

void apmon_pretty_open_object(struct apmon_pretty *p, const char *key)
{
	open_container(p, key, 1);
}

void apmon_pretty_open_array(struct apmon_pretty *p, const char *key)
{
	open_container(p, key, 0);
}

void apmon_pretty_close(struct apmon_pretty *p)
{
	int is_object;
	int had_elements;

	if (p->depth == 0) {
		p->failed = 1;
		return;
	}
	is_object = p->is_object[p->depth];
	had_elements = p->count[p->depth] > 0;
	p->depth--;
	if (had_elements) {
		put(p, "\n", 1);
		indent(p);
	}
	if (is_object) {
		put(p, "}", 1);
	} else {
		put(p, "]", 1);
	}
	if (p->depth == 0) {
		put(p, "\n", 1);
	}
}

void apmon_pretty_string(struct apmon_pretty *p, const char *key, const char *value)
{
	element(p, key);
	put_string(p, value);
}

/* A number, true, false or null, written as given */
void apmon_pretty_raw(struct apmon_pretty *p, const char *key, const char *value)
{
	element(p, key);
	puts_(p, value);
}

void apmon_pretty_int(struct apmon_pretty *p, const char *key, long long value)
{
	char text[32];

	snprintf(text, sizeof(text), "%lld", value);
	apmon_pretty_raw(p, key, text);
}

void apmon_pretty_double(struct apmon_pretty *p, const char *key, double value)
{
	char text[64];

	snprintf(text, sizeof(text), "%.15g", value);
	apmon_pretty_raw(p, key, text);
}

void apmon_pretty_bool(struct apmon_pretty *p, const char *key, int value)
{
	if (value) {
		apmon_pretty_raw(p, key, "true");
	} else {
		apmon_pretty_raw(p, key, "false");
	}
}

const char *apmon_pretty_text(struct apmon_pretty *p)
{
	if (p->failed || p->buf == NULL) {
		return NULL;
	}
	return p->buf;
}
