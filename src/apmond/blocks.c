/*
 * apmond extension blocks: named JSON objects that other programs (for example a future mesh11sd)
 * attach to this node's reports with ubus call apmond add_block '{"name":"mesh","data":{...},"ttl":120}'.
 * They are sent under "blocks": { "<name>": {...} } in every report, kept in RAM only,
 * and expire ttl seconds after they were last set (no ttl = until removed or apmond restarts).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg_json.h>

#include "apmond.h"

#define MAX_BLOCKS 16

struct block {
	char name[APMON_BLOCK_NAME_MAX + 1];
	char *json;
	uint64_t expires_mono_ms;   /* 0 = no expiry */
	uint64_t set_mono_ms;
};

static struct block blocks[MAX_BLOCKS];

static void block_clear(struct block *b)
{
	free(b->json);
	memset(b, 0, sizeof(*b));
}

static void expire_blocks(void)
{
	uint64_t now = apmon_monotonic_ms();
	int i;

	for (i = 0; i < MAX_BLOCKS; i++) {
		struct block *b = &blocks[i];

		if (b->name[0] == '\0' || b->expires_mono_ms == 0) {
			continue;
		}
		if (now >= b->expires_mono_ms) {
			LOG_INFO_("block %s expired", b->name);
			block_clear(b);
		}
	}
}

static struct block *find_block(const char *name)
{
	int i;

	for (i = 0; i < MAX_BLOCKS; i++) {
		if (strcmp(blocks[i].name, name) == 0) {
			return &blocks[i];
		}
	}
	return NULL;
}

/* Returns 0, or a UBUS_STATUS_* error */
int apmond_block_set(const char *name, struct blob_attr *data, int ttl)
{
	struct block *b;
	char *json;

	if (!apmon_block_name_valid(name)) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (blobmsg_type(data) != BLOBMSG_TYPE_TABLE) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	json = blobmsg_format_json(data, true);
	if (json == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
	if (strlen(json) > APMON_BLOCK_DATA_MAX) {
		free(json);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	expire_blocks();
	b = find_block(name);
	if (b == NULL) {
		b = find_block("");
	}
	if (b == NULL) {
		free(json);
		return UBUS_STATUS_NO_DATA;
	}

	free(b->json);
	snprintf(b->name, sizeof(b->name), "%s", name);
	b->json = json;
	b->set_mono_ms = apmon_monotonic_ms();
	b->expires_mono_ms = 0;
	if (ttl > 0) {
		b->expires_mono_ms = b->set_mono_ms + (uint64_t)ttl * 1000;
	}
	LOG_INFO_("block %s set (%zu bytes, ttl %d)", name, strlen(json), ttl);
	return 0;
}

int apmond_block_remove(const char *name)
{
	struct block *b;

	if (!apmon_block_name_valid(name)) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	b = find_block(name);
	if (b == NULL) {
		return UBUS_STATUS_NOT_FOUND;
	}
	block_clear(b);
	LOG_INFO_("block %s removed", name);
	return 0;
}

/* "blocks": { "<name>": <json>, ... } for the report */
void apmond_blocks_json(struct apmon_json *j)
{
	int i;

	expire_blocks();
	apmon_json_open_object(j, "blocks");
	for (i = 0; i < MAX_BLOCKS; i++) {
		if (blocks[i].name[0] != '\0') {
			apmon_json_raw(j, blocks[i].name, blocks[i].json);
		}
	}
	apmon_json_close_object(j);
}

/* Local block names and expiry, for ubus status */
void apmond_blocks_list(struct blob_buf *b)
{
	uint64_t now = apmon_monotonic_ms();
	void *arr;
	int i;

	expire_blocks();
	arr = blobmsg_open_array(b, "blocks");
	for (i = 0; i < MAX_BLOCKS; i++) {
		void *t;

		if (blocks[i].name[0] == '\0') {
			continue;
		}
		t = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "name", blocks[i].name);
		blobmsg_add_u32(b, "bytes", (uint32_t)strlen(blocks[i].json));
		if (blocks[i].expires_mono_ms > 0) {
			blobmsg_add_u32(b, "expires_in_s", (uint32_t)((blocks[i].expires_mono_ms - now) / 1000));
		}
		blobmsg_close_table(b, t);
	}
	blobmsg_close_array(b, arr);
}
