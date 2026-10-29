/*
 * Host unit tests for libapmon: crypto against tests/vectors, envelope round trip,
 * replay rejection and negative cases. Run: make -C tests check
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apmon.h"
#include "vectors/vectors.h"

static int failures;
static int passes;

#define CHECK(cond, name) check((cond), (name), __LINE__)

static void check(int ok, const char *name, int line)
{
	if (ok) {
		passes++;
		printf("ok   %s\n", name);
	} else {
		failures++;
		printf("FAIL %s (line %d)\n", name, line);
	}
}

static uint8_t *hex_alloc(const char *hex, size_t *len)
{
	size_t n = strlen(hex) / 2;
	uint8_t *buf = malloc(n);

	if (buf == NULL || apmon_hex_decode(hex, buf, n) != 0) {
		fprintf(stderr, "bad hex\n");
		exit(2);
	}
	*len = n;
	return buf;
}

static int bytes_equal_hex(const uint8_t *bytes, size_t len, const char *hex)
{
	char *out = malloc(2 * len + 1);
	int same;

	apmon_hex_encode(bytes, len, out);
	same = strcmp(out, hex) == 0;
	free(out);
	return same;
}

static void test_rfc5869(void)
{
	uint8_t ikm[22];
	uint8_t salt[13];
	uint8_t info[10];
	uint8_t prk[32];
	uint8_t okm[42];
	int i;

	for (i = 0; i < 22; i++) {
		ikm[i] = 0x0b;
	}
	for (i = 0; i < 13; i++) {
		salt[i] = (uint8_t)i;
	}
	for (i = 0; i < 10; i++) {
		info[i] = (uint8_t)(0xf0 + i);
	}

	apmon_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
	CHECK(bytes_equal_hex(prk, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
	      "HKDF RFC 5869 A.1 PRK");

	apmon_hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));
	CHECK(bytes_equal_hex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
				       "34007208d5b887185865"),
	      "HKDF RFC 5869 A.1 OKM");
}

static void test_keys(const char *pass, const char *ikm_hex, const char *ks_hex, const char *kc_hex, const char *name)
{
	struct apmon_keys keys;
	uint8_t ikm[32];
	char label[128];

	apmon_pbkdf2_sha256((const uint8_t *)pass, strlen(pass), (const uint8_t *)APMON_PBKDF2_SALT,
			    strlen(APMON_PBKDF2_SALT), APMON_PBKDF2_ITERATIONS, ikm, sizeof(ikm));
	snprintf(label, sizeof(label), "PBKDF2 IKM (%s)", name);
	CHECK(bytes_equal_hex(ikm, 32, ikm_hex), label);

	CHECK(apmon_derive_keys(pass, 0, &keys) == 0, "derive_keys returns 0");
	snprintf(label, sizeof(label), "K_s2c (%s)", name);
	CHECK(bytes_equal_hex(keys.s2c, 32, ks_hex), label);
	snprintf(label, sizeof(label), "K_c2s (%s)", name);
	CHECK(bytes_equal_hex(keys.c2s, 32, kc_hex), label);
}

static void test_vector_message(void)
{
	struct apmon_header h;
	uint8_t key[32];
	uint8_t *msg;
	uint8_t *sealed;
	size_t msg_len;
	size_t sealed_len;
	char *pt = NULL;
	size_t pt_len = 0;

	apmon_hex_decode(TV_CHBS_K_S2C, key, sizeof(key));
	msg = hex_alloc(TV_REPORT_MESSAGE, &msg_len);

	CHECK(apmon_open(key, msg, msg_len, &h, &pt, &pt_len) == APMON_OK, "open REPORT test vector");
	CHECK(pt != NULL && strcmp(pt, TV_REPORT_PLAINTEXT) == 0, "REPORT plaintext matches");
	CHECK(h.type == APMON_TYPE_REPORT && h.seq == 42 && h.timestamp_ms == 1793270400000ULL, "REPORT header fields");

	/* Re-seal with the same fixed nonce: must be byte-identical (backend conformance) */
	CHECK(apmon_seal_with_nonce(key, &h, pt, pt_len, &sealed, &sealed_len) == APMON_OK, "seal with fixed nonce");
	CHECK(sealed_len == msg_len && memcmp(sealed, msg, msg_len) == 0, "sealed bytes equal test vector");

	free(sealed);
	free(pt);
	free(msg);
}

static void test_negative(void)
{
	struct apmon_header h;
	uint8_t key[32];
	uint8_t *msg;
	size_t msg_len;
	char *pt = NULL;
	size_t i;
	int all_fail = 1;

	apmon_hex_decode(TV_CHBS_K_S2C, key, sizeof(key));
	msg = hex_alloc(TV_REPORT_MESSAGE, &msg_len);

	/* Flip one bit in every authenticated header byte that does not fail decoding first */
	for (i = 8; i < APMON_HEADER_LEN - 4; i++) {
		enum apmon_result r;

		if (i == 18 || i == 19) {
			continue;
		}
		msg[i] ^= 0x01;
		r = apmon_open(key, msg, msg_len, &h, &pt, NULL);
		if (r != APMON_ERR_AUTH) {
			all_fail = 0;
		}
		msg[i] ^= 0x01;
	}
	CHECK(all_fail, "flipped header byte -> AUTH error");

	msg[APMON_HEADER_LEN + 3] ^= 0x80;
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_AUTH, "flipped ciphertext byte -> AUTH error");
	msg[APMON_HEADER_LEN + 3] ^= 0x80;

	msg[msg_len - 1] ^= 0x01;
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_AUTH, "flipped tag byte -> AUTH error");
	msg[msg_len - 1] ^= 0x01;

	CHECK(apmon_open(key, msg, msg_len - 1, &h, &pt, NULL) == APMON_ERR_MALFORMED, "truncated body -> MALFORMED");

	msg[0] = 'X';
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_MALFORMED, "bad magic -> MALFORMED");
	msg[0] = 'A';

	msg[4] = 3;
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_VERSION, "version 3 -> VERSION");
	msg[4] = 2;

	msg[7] |= 0x04;
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_MALFORMED, "reserved flag bit -> MALFORMED");
	msg[7] &= (uint8_t)~0x04;

	msg[19] = 1;
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_MALFORMED, "reserved bytes -> MALFORMED");
	msg[19] = 0;

	key[0] ^= 1;
	CHECK(apmon_open(key, msg, msg_len, &h, &pt, NULL) == APMON_ERR_AUTH, "wrong key -> AUTH");

	CHECK(apmon_open(key, msg, 10, &h, &pt, NULL) == APMON_ERR_MALFORMED, "short message -> MALFORMED");

	free(msg);
}

static void test_round_trip_and_replay(void)
{
	struct apmon_keys keys;
	struct apmon_header h;
	struct apmon_header got;
	struct apmon_replay replay;
	uint8_t *msg1;
	uint8_t *msg2;
	size_t len1;
	size_t len2;
	char *pt = NULL;
	const char *text = "{\"v\":2,\"type\":\"report\"}";
	uint64_t now = 1793270400000ULL;

	apmon_hex_decode(TV_CHBS_K_S2C, keys.s2c, 32);
	apmon_hex_decode(TV_CHBS_K_C2S, keys.c2s, 32);

	memset(&h, 0, sizeof(h));
	h.type = APMON_TYPE_REPORT;
	apmon_mac_parse("94:83:c4:a1:b2:c3", h.sender_id);
	h.timestamp_ms = now;
	h.seq = 1;

	CHECK(apmon_seal(keys.s2c, &h, text, strlen(text), &msg1, &len1) == APMON_OK, "seal random nonce");
	CHECK(apmon_seal(keys.s2c, &h, text, strlen(text), &msg2, &len2) == APMON_OK, "seal again");
	CHECK(memcmp(msg1 + 32, msg2 + 32, APMON_NONCE_LEN) != 0, "nonces differ between messages");

	CHECK(apmon_open(keys.s2c, msg1, len1, &got, &pt, NULL) == APMON_OK && strcmp(pt, text) == 0, "round trip");
	free(pt);
	pt = NULL;
	CHECK(apmon_open(keys.c2s, msg1, len1, &got, &pt, NULL) == APMON_ERR_AUTH, "other direction key -> AUTH");

	apmon_replay_init(&replay, 4, 120000);
	apmon_header_decode(msg1, len1, &got);
	CHECK(apmon_replay_check(&replay, &got, now + 1000, 1) == APMON_OK, "first message accepted");
	CHECK(apmon_replay_check(&replay, &got, now + 2000, 1) == APMON_ERR_REPLAY, "same message again -> REPLAY");
	CHECK(apmon_replay_check(&replay, &got, now + 241000, 0) == APMON_OK, "nonce forgotten after 2 x max_skew");

	apmon_header_decode(msg2, len2, &got);
	CHECK(apmon_replay_check(&replay, &got, now + 121000, 1) == APMON_ERR_TIME, "timestamp +121 s -> TIME");
	CHECK(apmon_replay_check(&replay, &got, now - 121000, 1) == APMON_ERR_TIME, "timestamp -121 s -> TIME");
	CHECK(apmon_replay_check(&replay, &got, now + 119000, 1) == APMON_OK, "timestamp +119 s accepted");
	got.nonce[0] ^= 0x01;
	CHECK(apmon_replay_check(&replay, &got, now + 999999, 0) == APMON_OK, "TIME_REQ (no window check) accepted far out");
	CHECK(apmon_replay_check(&replay, &got, now + 999999, 0) == APMON_ERR_REPLAY, "TIME_REQ nonce reuse -> REPLAY");

	apmon_replay_free(&replay);
	free(msg1);
	free(msg2);
}

static void test_json(void)
{
	struct apmon_json j;

	apmon_json_init(&j);
	apmon_json_open_object(&j, NULL);
	apmon_json_int(&j, "v", 2);
	apmon_json_string(&j, "s", "a\"b\\c\n");
	apmon_json_open_array(&j, "list");
	apmon_json_int(&j, NULL, 1);
	apmon_json_bool(&j, NULL, 0);
	apmon_json_null(&j, NULL);
	apmon_json_close_array(&j);
	apmon_json_open_object(&j, "o");
	apmon_json_close_object(&j);
	apmon_json_close_object(&j);

	CHECK(!j.failed && strcmp(j.buf, "{\"v\":2,\"s\":\"a\\\"b\\\\c\\u000a\",\"list\":[1,false,null],\"o\":{}}") == 0,
	      "JSON writer output");
	apmon_json_free(&j);
}

int main(void)
{
	test_rfc5869();
	test_keys(TV_DEFAULT_PASSPHRASE, TV_DEFAULT_IKM, TV_DEFAULT_K_S2C, TV_DEFAULT_K_C2S, "built-in default");
	test_keys(TV_CHBS_PASSPHRASE, TV_CHBS_IKM, TV_CHBS_K_S2C, TV_CHBS_K_C2S, "correct horse");
	test_vector_message();
	test_negative();
	test_round_trip_and_replay();
	test_json();

	printf("\n%d passed, %d failed\n", passes, failures);
	if (failures > 0) {
		return 1;
	}
	return 0;
}
