/*
 * libapmon message envelope: 48-byte header (= AAD) + AES-256-GCM ciphertext + tag
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

static void put_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void put_u64(uint8_t *p, uint64_t v)
{
	put_u32(p, (uint32_t)(v >> 32));
	put_u32(p + 4, (uint32_t)v);
}

static uint16_t get_u16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p)
{
	return ((uint64_t)get_u32(p) << 32) | get_u32(p + 4);
}

void apmon_header_encode(const struct apmon_header *h, uint8_t out[APMON_HEADER_LEN])
{
	memcpy(out, APMON_MAGIC, 4);
	out[4] = h->version;
	out[5] = h->type;
	put_u16(out + 6, h->flags);
	put_u32(out + 8, h->key_epoch);
	memcpy(out + 12, h->sender_id, APMON_ID_LEN);
	out[18] = 0;
	out[19] = 0;
	put_u64(out + 20, h->timestamp_ms);
	put_u32(out + 28, h->seq);
	memcpy(out + 32, h->nonce, APMON_NONCE_LEN);
	put_u32(out + 44, h->ct_len);
}

enum apmon_result apmon_header_decode(const uint8_t *buf, size_t len, struct apmon_header *h)
{
	if (len < APMON_HEADER_LEN + APMON_TAG_LEN) {
		return APMON_ERR_MALFORMED;
	}
	if (memcmp(buf, APMON_MAGIC, 4) != 0) {
		return APMON_ERR_MALFORMED;
	}

	h->version = buf[4];
	h->type = buf[5];
	h->flags = get_u16(buf + 6);
	h->key_epoch = get_u32(buf + 8);
	memcpy(h->sender_id, buf + 12, APMON_ID_LEN);
	h->timestamp_ms = get_u64(buf + 20);
	h->seq = get_u32(buf + 28);
	memcpy(h->nonce, buf + 32, APMON_NONCE_LEN);
	h->ct_len = get_u32(buf + 44);

	if (h->version != APMON_VERSION) {
		return APMON_ERR_VERSION;
	}
	if (buf[18] != 0 || buf[19] != 0) {
		return APMON_ERR_MALFORMED;
	}
	if ((h->flags & ~APMON_FLAGS_KNOWN) != 0) {
		return APMON_ERR_MALFORMED;
	}
	if (h->ct_len != len - APMON_HEADER_LEN) {
		return APMON_ERR_MALFORMED;
	}
	return APMON_OK;
}

enum apmon_result apmon_seal_with_nonce(const uint8_t key[APMON_KEY_LEN], struct apmon_header *h,
					const char *plaintext, size_t pt_len, uint8_t **out, size_t *out_len)
{
	uint8_t *msg;
	size_t total = APMON_HEADER_LEN + pt_len + APMON_TAG_LEN;

	h->version = APMON_VERSION;
	h->ct_len = (uint32_t)(pt_len + APMON_TAG_LEN);

	msg = malloc(total);
	if (msg == NULL) {
		return APMON_ERR_NOMEM;
	}

	apmon_header_encode(h, msg);

	if (apmon_gcm_seal(key, h->nonce, msg, APMON_HEADER_LEN, (const uint8_t *)plaintext, pt_len,
			   msg + APMON_HEADER_LEN) != 0) {
		free(msg);
		return APMON_ERR_CRYPTO;
	}

	*out = msg;
	*out_len = total;
	return APMON_OK;
}

enum apmon_result apmon_seal(const uint8_t key[APMON_KEY_LEN], struct apmon_header *h,
			     const char *plaintext, size_t pt_len, uint8_t **out, size_t *out_len)
{
	if (apmon_random(h->nonce, APMON_NONCE_LEN) != 0) {
		return APMON_ERR_CRYPTO;
	}
	return apmon_seal_with_nonce(key, h, plaintext, pt_len, out, out_len);
}

enum apmon_result apmon_open(const uint8_t key[APMON_KEY_LEN], const uint8_t *msg, size_t msg_len,
			     struct apmon_header *h, char **plaintext, size_t *pt_len)
{
	enum apmon_result res;
	size_t len;
	char *pt;

	res = apmon_header_decode(msg, msg_len, h);
	if (res != APMON_OK) {
		return res;
	}

	len = h->ct_len - APMON_TAG_LEN;
	pt = malloc(len + 1);
	if (pt == NULL) {
		return APMON_ERR_NOMEM;
	}

	if (apmon_gcm_open(key, h->nonce, msg, APMON_HEADER_LEN, msg + APMON_HEADER_LEN, h->ct_len,
			   (uint8_t *)pt) != 0) {
		free(pt);
		return APMON_ERR_AUTH;
	}

	pt[len] = '\0';
	*plaintext = pt;
	if (pt_len != NULL) {
		*pt_len = len;
	}
	return APMON_OK;
}
