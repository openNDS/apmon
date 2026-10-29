/*
 * libapmon replay protection: timestamp window + (sender, nonce) cache
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

int apmon_replay_init(struct apmon_replay *r, size_t size, uint64_t max_skew_ms)
{
	r->entries = calloc(size, sizeof(*r->entries));
	if (r->entries == NULL) {
		return -1;
	}
	r->size = size;
	r->max_skew_ms = max_skew_ms;
	return 0;
}

void apmon_replay_free(struct apmon_replay *r)
{
	free(r->entries);
	r->entries = NULL;
	r->size = 0;
}

/*
 * Call only after the GCM tag has verified.
 * check_window = 0 for TIME_REQ, which is checked for nonce reuse but not for the time window.
 * On APMON_OK the nonce is remembered for 2 x max_skew.
 */
enum apmon_result apmon_replay_check(struct apmon_replay *r, const struct apmon_header *h, uint64_t now_ms,
				     int check_window)
{
	struct apmon_replay_entry *free_slot = NULL;
	struct apmon_replay_entry *oldest = NULL;
	struct apmon_replay_entry *slot;
	size_t i;

	if (check_window) {
		uint64_t diff;

		if (h->timestamp_ms > now_ms) {
			diff = h->timestamp_ms - now_ms;
		} else {
			diff = now_ms - h->timestamp_ms;
		}
		if (diff > r->max_skew_ms) {
			return APMON_ERR_TIME;
		}
	}

	for (i = 0; i < r->size; i++) {
		struct apmon_replay_entry *e = &r->entries[i];

		if (e->expires_ms <= now_ms) {
			if (free_slot == NULL) {
				free_slot = e;
			}
			continue;
		}

		if (memcmp(e->nonce, h->nonce, APMON_NONCE_LEN) == 0 &&
		    memcmp(e->sender_id, h->sender_id, APMON_ID_LEN) == 0) {
			return APMON_ERR_REPLAY;
		}

		if (oldest == NULL || e->expires_ms < oldest->expires_ms) {
			oldest = e;
		}
	}

	slot = free_slot;
	if (slot == NULL) {
		slot = oldest;
	}

	/* Cache full: the oldest entry is evicted (size the cache for nodes x 240 s / interval) */
	if (slot != NULL) {
		memcpy(slot->sender_id, h->sender_id, APMON_ID_LEN);
		memcpy(slot->nonce, h->nonce, APMON_NONCE_LEN);
		slot->expires_ms = now_ms + 2 * r->max_skew_ms;
	}
	return APMON_OK;
}
