/*
 * libapmon crypto backend: OpenSSL 3 (EVP APIs only, nothing deprecated)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include "apmon.h"

const char *apmon_crypto_backend(void)
{
	return "OpenSSL " OPENSSL_FULL_VERSION_STR;
}

int apmon_random(void *buf, size_t len)
{
	if (len > (size_t)0x7fffffff) {
		return -1;
	}
	if (RAND_bytes(buf, (int)len) != 1) {
		return -1;
	}
	return 0;
}

int apmon_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
			unsigned int iterations, uint8_t *out, size_t out_len)
{
	if (pw_len > 0x7fffffff || salt_len > 0x7fffffff || out_len > 0x7fffffff || iterations > 0x7fffffff) {
		return -1;
	}
	if (PKCS5_PBKDF2_HMAC((const char *)pw, (int)pw_len, salt, (int)salt_len, (int)iterations,
			      EVP_sha256(), (int)out_len, out) != 1) {
		return -1;
	}
	return 0;
}

int apmon_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32])
{
	unsigned int out_len = 32;

	if (key_len > 0x7fffffff) {
		return -1;
	}
	/* HMAC() is the one-shot EVP_MAC wrapper in OpenSSL 3, not deprecated */
	if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len) == NULL || out_len != 32) {
		return -1;
	}
	return 0;
}

int apmon_gcm_seal(const uint8_t key[APMON_KEY_LEN], const uint8_t nonce[APMON_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct_tag)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len = 0;
	int ok = 0;

	if (ctx == NULL || aad_len > 0x7fffffff || pt_len > 0x7fffffff) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, APMON_NONCE_LEN, NULL) == 1 &&
	    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1) {
		ok = 1;
	}
	if (ok && aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
		ok = 0;
	}
	if (ok && pt_len > 0 && EVP_EncryptUpdate(ctx, ct_tag, &len, pt, (int)pt_len) != 1) {
		ok = 0;
	}
	if (ok && EVP_EncryptFinal_ex(ctx, ct_tag + pt_len, &len) != 1) {
		ok = 0;
	}
	if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, APMON_TAG_LEN, ct_tag + pt_len) != 1) {
		ok = 0;
	}
	EVP_CIPHER_CTX_free(ctx);
	if (!ok) {
		return -1;
	}
	return 0;
}

int apmon_gcm_open(const uint8_t key[APMON_KEY_LEN], const uint8_t nonce[APMON_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *ct_tag, size_t ct_tag_len, uint8_t *pt)
{
	EVP_CIPHER_CTX *ctx;
	uint8_t tag[APMON_TAG_LEN];
	size_t ct_len;
	int len = 0;
	int ok = 0;

	if (ct_tag_len < APMON_TAG_LEN || aad_len > 0x7fffffff || ct_tag_len > 0x7fffffff) {
		return -1;
	}
	ct_len = ct_tag_len - APMON_TAG_LEN;
	memcpy(tag, ct_tag + ct_len, APMON_TAG_LEN);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		return -1;
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, APMON_NONCE_LEN, NULL) == 1 &&
	    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1) {
		ok = 1;
	}
	if (ok && aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
		ok = 0;
	}
	if (ok && ct_len > 0 && EVP_DecryptUpdate(ctx, pt, &len, ct_tag, (int)ct_len) != 1) {
		ok = 0;
	}
	if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, APMON_TAG_LEN, tag) != 1) {
		ok = 0;
	}
	/* the tag is checked here; on failure pt holds unauthenticated data the caller must drop */
	if (ok && EVP_DecryptFinal_ex(ctx, pt + ct_len, &len) != 1) {
		ok = 0;
	}
	EVP_CIPHER_CTX_free(ctx);
	if (!ok) {
		OPENSSL_cleanse(pt, ct_len);
		return -1;
	}
	return 0;
}

int apmon_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
	unsigned int out_len = 0;

	if (EVP_Digest(data, len, out, &out_len, EVP_sha256(), NULL) != 1 || out_len != 32) {
		return -1;
	}
	return 0;
}

int apmon_sha256_file(const char *path, char hex[65])
{
	EVP_MD_CTX *ctx;
	unsigned char buf[4096];
	uint8_t digest[32];
	unsigned int digest_len = 0;
	size_t n;
	FILE *f;
	int rc = 0;

	hex[0] = '\0';
	f = fopen(path, "rb");
	if (f == NULL) {
		return -1;
	}
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		rc = -1;
	}
	while (rc == 0 && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
		if (EVP_DigestUpdate(ctx, buf, n) != 1) {
			rc = -1;
		}
	}
	if (rc == 0 && ferror(f)) {
		rc = -1;
	}
	if (rc == 0 && (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32)) {
		rc = -1;
	}
	EVP_MD_CTX_free(ctx);
	fclose(f);

	if (rc == 0) {
		apmon_hex_encode(digest, sizeof(digest), hex);
	}
	return rc;
}
