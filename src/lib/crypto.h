/*
 * libapmon crypto interface: everything apmon needs from a crypto library, and nothing more.
 * One backend is compiled in (CMake CRYPTO_BACKEND, tests/Makefile CRYPTO): crypto_mbedtls.c
 * or crypto_openssl.c. Both are wire compatible (same algorithms and parameters, checked
 * against the same test vectors); only the backend files include mbedtls or OpenSSL headers.
 * HKDF (kdf.c) is built on apmon_hmac_sha256, so it is the same code over either backend.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Name of the compiled-in backend, eg "mbedtls 3.6.7" or "OpenSSL 3.5.7" */
const char *apmon_crypto_backend(void);

/* Cryptographically secure random bytes; 0 or -1 */
int apmon_random(void *buf, size_t len);

/* PBKDF2-HMAC-SHA256 */
int apmon_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
			unsigned int iterations, uint8_t *out, size_t out_len);

/* HMAC-SHA256 (the HKDF in kdf.c is built on it) */
int apmon_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
		      uint8_t out[32]);

/*
 * AES-256-GCM, 12 byte nonce, 16 byte tag appended to the ciphertext.
 * seal: ct_tag gets pt_len + 16 bytes. open: -1 if the tag does not verify.
 */
int apmon_gcm_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
		   const uint8_t *pt, size_t pt_len, uint8_t *ct_tag);
int apmon_gcm_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
		   const uint8_t *ct_tag, size_t ct_tag_len, uint8_t *pt);

/* SHA-256 of a buffer, and of a file (streamed) as lowercase hex as sha256sum prints it */
int apmon_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
int apmon_sha256_file(const char *path, char hex[65]);
