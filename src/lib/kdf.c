/*
 * libapmon key derivation: PBKDF2-HMAC-SHA256 then HKDF-SHA256 (RFC 5869)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <string.h>

#include "apmon.h"

int apmon_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[32])
{
	return apmon_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int apmon_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
	uint8_t block[32];
	uint8_t input[32 + 256 + 1];
	size_t done = 0;
	size_t prev_len = 0;
	uint8_t counter = 1;

	if (info_len > 256 || out_len > 255 * 32) {
		return -1;
	}

	while (done < out_len) {
		size_t n = 0;
		size_t take;

		/* T(i) = HMAC(PRK, T(i-1) | info | i) */
		memcpy(input, block, prev_len);
		n += prev_len;
		memcpy(input + n, info, info_len);
		n += info_len;
		input[n] = counter;
		n += 1;

		if (apmon_hmac_sha256(prk, 32, input, n, block) != 0) {
			return -1;
		}

		take = out_len - done;
		if (take > 32) {
			take = 32;
		}
		memcpy(out + done, block, take);
		done += take;
		prev_len = 32;
		counter++;
	}
	return 0;
}

static int expand_with_epoch(const uint8_t prk[32], const char *label, uint32_t epoch, uint8_t out[APMON_KEY_LEN])
{
	uint8_t info[64];
	size_t label_len = strlen(label);

	memcpy(info, label, label_len);
	info[label_len] = (uint8_t)(epoch >> 24);
	info[label_len + 1] = (uint8_t)(epoch >> 16);
	info[label_len + 2] = (uint8_t)(epoch >> 8);
	info[label_len + 3] = (uint8_t)epoch;

	return apmon_hkdf_expand(prk, info, label_len + 4, out, APMON_KEY_LEN);
}

static int derive_prk(const char *passphrase, uint8_t prk[32])
{
	uint8_t ikm[32];
	int ret = -1;

	if (apmon_pbkdf2_sha256((const uint8_t *)passphrase, strlen(passphrase),
				(const uint8_t *)APMON_PBKDF2_SALT, strlen(APMON_PBKDF2_SALT),
				APMON_PBKDF2_ITERATIONS, ikm, sizeof(ikm)) == 0) {
		ret = apmon_hkdf_extract((const uint8_t *)APMON_HKDF_SALT, strlen(APMON_HKDF_SALT), ikm, sizeof(ikm), prk);
	}
	memset(ikm, 0, sizeof(ikm));
	return ret;
}

static int keys_from_prk(const uint8_t prk[32], uint32_t epoch, struct apmon_keys *keys)
{
	keys->epoch = epoch;

	if (expand_with_epoch(prk, APMON_INFO_S2C, epoch, keys->s2c) != 0) {
		return -1;
	}
	if (expand_with_epoch(prk, APMON_INFO_C2S, epoch, keys->c2s) != 0) {
		return -1;
	}
	return 0;
}

int apmon_derive_keys(const char *passphrase, uint32_t epoch, struct apmon_keys *keys)
{
	uint8_t prk[32];
	int ret = -1;

	if (derive_prk(passphrase, prk) == 0) {
		ret = keys_from_prk(prk, epoch, keys);
	}
	memset(prk, 0, sizeof(prk));
	return ret;
}

/* previous is left zeroed with epoch 0 when epoch is 0 (there is no previous epoch) */
int apmon_derive_keys_with_previous(const char *passphrase, uint32_t epoch, struct apmon_keys *current,
				    struct apmon_keys *previous)
{
	uint8_t prk[32];
	int ret = -1;

	memset(previous, 0, sizeof(*previous));

	if (derive_prk(passphrase, prk) == 0) {
		ret = keys_from_prk(prk, epoch, current);
		if (ret == 0 && epoch > 0) {
			ret = keys_from_prk(prk, epoch - 1, previous);
		}
	}
	memset(prk, 0, sizeof(prk));
	return ret;
}
