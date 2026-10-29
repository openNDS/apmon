/*
 * libapmon crypto backend: mbedtls (OpenWrt default)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <errno.h>

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include "apmon.h"

int apmon_random(void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = getrandom(p, len, 0);

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

int apmon_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
			unsigned int iterations, uint8_t *out, size_t out_len)
{
	int ret;

	ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, pw, pw_len, salt, salt_len,
					    iterations, (uint32_t)out_len, out);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

int apmon_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32])
{
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	if (md == NULL) {
		return -1;
	}
	if (mbedtls_md_hmac(md, key, key_len, data, data_len, out) != 0) {
		return -1;
	}
	return 0;
}

int apmon_gcm_seal(const uint8_t key[APMON_KEY_LEN], const uint8_t nonce[APMON_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct_tag)
{
	mbedtls_gcm_context gcm;
	int ret;

	mbedtls_gcm_init(&gcm);
	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, APMON_KEY_LEN * 8);
	if (ret == 0) {
		ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt_len, nonce, APMON_NONCE_LEN,
						aad, aad_len, pt, ct_tag, APMON_TAG_LEN, ct_tag + pt_len);
	}
	mbedtls_gcm_free(&gcm);

	if (ret != 0) {
		return -1;
	}
	return 0;
}

int apmon_gcm_open(const uint8_t key[APMON_KEY_LEN], const uint8_t nonce[APMON_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *ct_tag, size_t ct_tag_len, uint8_t *pt)
{
	mbedtls_gcm_context gcm;
	size_t ct_len;
	int ret;

	if (ct_tag_len < APMON_TAG_LEN) {
		return -1;
	}
	ct_len = ct_tag_len - APMON_TAG_LEN;

	mbedtls_gcm_init(&gcm);
	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, APMON_KEY_LEN * 8);
	if (ret == 0) {
		ret = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, APMON_NONCE_LEN, aad, aad_len,
					       ct_tag + ct_len, APMON_TAG_LEN, ct_tag, pt);
	}
	mbedtls_gcm_free(&gcm);

	if (ret != 0) {
		return -1;
	}
	return 0;
}

int apmon_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	if (md == NULL) {
		return -1;
	}
	if (mbedtls_md(md, data, len, out) != 0) {
		return -1;
	}
	return 0;
}

/* sha256 of a file as lowercase hex (as sha256sum); 0 on success, -1 if it cannot be read */
int apmon_sha256_file(const char *path, char hex[65])
{
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_context_t ctx;
	unsigned char buf[4096];
	uint8_t digest[32];
	size_t n;
	FILE *f;
	int rc = 0;

	hex[0] = '\0';
	if (md == NULL) {
		return -1;
	}
	f = fopen(path, "rb");
	if (f == NULL) {
		return -1;
	}

	mbedtls_md_init(&ctx);
	if (mbedtls_md_setup(&ctx, md, 0) != 0 || mbedtls_md_starts(&ctx) != 0) {
		rc = -1;
	}
	while (rc == 0 && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
		if (mbedtls_md_update(&ctx, buf, n) != 0) {
			rc = -1;
		}
	}
	if (rc == 0 && ferror(f)) {
		rc = -1;
	}
	if (rc == 0 && mbedtls_md_finish(&ctx, digest) != 0) {
		rc = -1;
	}
	mbedtls_md_free(&ctx);
	fclose(f);

	if (rc == 0) {
		apmon_hex_encode(digest, sizeof(digest), hex);
	}
	return rc;
}
