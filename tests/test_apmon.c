/*
 * Host unit tests for libapmon: crypto against tests/vectors, envelope round trip,
 * replay rejection and negative cases. Run: make -C tests check
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

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

static void test_extra(void)
{
	struct apmon_keys cur;
	struct apmon_keys prev;
	struct apmon_keys direct;
	struct apmon_table t;
	uint8_t prefix[8];
	uint8_t mac[6];
	uint8_t iid[8];
	char hex[17];
	char age[16];
	char out[256];

	/* apmond 1.x put the default passphrase's collector on fd46:cfe5:34c5:6ddd::1 */
	CHECK(apmon_ula_prefix(TV_DEFAULT_PASSPHRASE, prefix) == 0, "ULA prefix derived");
	apmon_hex_encode(prefix, 8, hex);
	CHECK(strcmp(hex, "fd46cfe534c56ddd") == 0, "ULA prefix matches apmond 1.x");

	apmon_mac_parse("52:54:00:12:34:01", mac);
	apmon_eui64_iid(mac, iid);
	apmon_hex_encode(iid, 8, hex);
	CHECK(strcmp(hex, "505400fffe123401") == 0, "EUI-64 interface id");

	CHECK(apmon_block_name_valid("mesh"), "block name mesh valid");
	CHECK(apmon_block_name_valid("mesh_11-s2"), "block name with _ - digits valid");
	CHECK(!apmon_block_name_valid(""), "empty block name invalid");
	CHECK(!apmon_block_name_valid("Mesh"), "upper case block name invalid");
	CHECK(!apmon_block_name_valid("a.b"), "dot in block name invalid");
	CHECK(!apmon_block_name_valid("a b"), "space in block name invalid");
	CHECK(!apmon_block_name_valid("abcdefghijklmnopqrstuvwxyz0123456"), "33 character block name invalid");
	CHECK(apmon_block_name_valid("abcdefghijklmnopqrstuvwxyz012345"), "32 character block name valid");

	CHECK(apmon_node_cmp(1, "zz", "b", 0, "aa", "a") < 0, "collector sorts first");
	CHECK(apmon_node_cmp(0, "aa", "b", 1, "zz", "a") > 0, "collector sorts first (reversed)");
	CHECK(apmon_node_cmp(0, "ap-1", "b", 0, "ap-2", "a") < 0, "nodes sort by hostname");
	CHECK(apmon_node_cmp(0, "ap", "a", 0, "ap", "b") < 0, "same hostname sorts by id");

	{
		struct apmon_pretty pj;
		const char *want =
			"{\n"
			"  \"name\": \"ap \\\"1\\\"\\\\x\\n\\u0001\",\n"
			"  \"n\": -3,\n"
			"  \"ok\": true,\n"
			"  \"none\": null,\n"
			"  \"load\": 0.5,\n"
			"  \"empty_obj\": {},\n"
			"  \"empty_arr\": [],\n"
			"  \"nodes\": [\n"
			"    {\n"
			"      \"id\": \"a\",\n"
			"      \"clients\": [\n"
			"        1,\n"
			"        2\n"
			"      ]\n"
			"    },\n"
			"    {\n"
			"      \"blocks\": {}\n"
			"    }\n"
			"  ]\n"
			"}\n";

		apmon_pretty_init(&pj);
		apmon_pretty_open_object(&pj, NULL);
		apmon_pretty_string(&pj, "name", "ap \"1\"\\x\n\001");
		apmon_pretty_int(&pj, "n", -3);
		apmon_pretty_bool(&pj, "ok", 1);
		apmon_pretty_raw(&pj, "none", "null");
		apmon_pretty_double(&pj, "load", 0.5);
		apmon_pretty_open_object(&pj, "empty_obj");
		apmon_pretty_close(&pj);
		apmon_pretty_open_array(&pj, "empty_arr");
		apmon_pretty_close(&pj);
		apmon_pretty_open_array(&pj, "nodes");
		apmon_pretty_open_object(&pj, NULL);
		apmon_pretty_string(&pj, "id", "a");
		apmon_pretty_open_array(&pj, "clients");
		apmon_pretty_int(&pj, NULL, 1);
		apmon_pretty_int(&pj, NULL, 2);
		apmon_pretty_close(&pj);
		apmon_pretty_close(&pj);
		apmon_pretty_open_object(&pj, NULL);
		apmon_pretty_open_object(&pj, "blocks");
		apmon_pretty_close(&pj);
		apmon_pretty_close(&pj);
		apmon_pretty_close(&pj);
		apmon_pretty_close(&pj);
		CHECK(apmon_pretty_text(&pj) != NULL && strcmp(apmon_pretty_text(&pj), want) == 0,
		      "pretty JSON: nesting, empty containers, escaping, arrays of objects");
		if (apmon_pretty_text(&pj) != NULL && strcmp(apmon_pretty_text(&pj), want) != 0) {
			printf("%s", apmon_pretty_text(&pj));
		}
		apmon_pretty_free(&pj);

		apmon_pretty_init(&pj);
		apmon_pretty_open_object(&pj, NULL);
		apmon_pretty_close(&pj);
		CHECK(apmon_pretty_text(&pj) != NULL && strcmp(apmon_pretty_text(&pj), "{}\n") == 0, "pretty JSON: empty reply");
		apmon_pretty_close(&pj);
		CHECK(apmon_pretty_text(&pj) == NULL, "pretty JSON: unbalanced close fails");
		apmon_pretty_free(&pj);
	}

	{
		uint16_t fl[3] = { 0, APMON_BRVLAN_PVID | APMON_BRVLAN_UNTAGGED, 0 };
		uint16_t vd[3] = { 20, 10, 30 };
		uint16_t trunk_fl[2] = { 0, 0 };
		uint16_t one_fl[2] = { 0, APMON_BRVLAN_UNTAGGED };
		uint16_t two_fl[2] = { APMON_BRVLAN_UNTAGGED, APMON_BRVLAN_UNTAGGED };

		CHECK(apmon_port_access_vlan(fl, vd, 3) == 10, "port VLAN: PVID wins");
		CHECK(apmon_port_access_vlan(trunk_fl, vd, 2) == 0, "port VLAN: tagged only (trunk) is none");
		CHECK(apmon_port_access_vlan(one_fl, vd, 2) == 10, "port VLAN: single untagged without PVID");
		CHECK(apmon_port_access_vlan(two_fl, vd, 2) == 0, "port VLAN: two untagged is ambiguous");
		CHECK(apmon_port_access_vlan(fl, vd, 0) == 0, "port VLAN: no entries");
		CHECK(apmon_vlan_from_name("br-lan.10") == 10, "VLAN from name br-lan.10");
		CHECK(apmon_vlan_from_name("eth0.20") == 20, "VLAN from name eth0.20");
		CHECK(apmon_vlan_from_name("br-lan") == 0, "VLAN from name br-lan");
		CHECK(apmon_vlan_from_name("phy0-ap0") == 0, "VLAN from name phy0-ap0");
		CHECK(apmon_vlan_from_name("eth0.5000") == 0, "VLAN from name out of range");
		CHECK(apmon_vlan_from_name("wlan0.sta1") == 0, "VLAN from name non-numeric");
	}

	{
		char date[64];

		setenv("TZ", "GMT0", 1);
		tzset();
		apmon_format_date(1793288820, date, sizeof(date));
		CHECK(strcmp(date, "Thu_Oct_29_15:47:00_GMT_2026") == 0, "date as 1.x date_time");
		apmon_format_date(1791546420, date, sizeof(date));
		CHECK(strcmp(date, "Fri_Oct__9_11:47:00_GMT_2026") == 0, "date with a one digit day, as date(1)");
	}

	CHECK(apmon_client_ordered_field("client_mac"), "client_mac is written first by the collector");
	CHECK(apmon_client_ordered_field("mac"), "pre-r8 mac is not copied again");
	CHECK(apmon_client_ordered_field("vxlan"), "vxlan is a location field");
	CHECK(apmon_client_ordered_field("ap_ssid"), "ap_ssid is a location field");
	CHECK(apmon_client_ordered_field("ap_ifname"), "ap_ifname is a location field");
	CHECK(apmon_client_ordered_field("ap_bssid"), "ap_bssid is a location field");
	CHECK(apmon_client_ordered_field("ap"), "pre-r9 ap is not copied again");
	CHECK(!apmon_client_ordered_field("signal_avg_dbm"), "stats follow as reported");
	CHECK(!apmon_client_ordered_field("speed_mbps"), "wired stats follow as reported");

	{
		int level = -1;

		CHECK(apmon_debuglevel_parse("0", &level) == 0 && level == 0, "debuglevel 0");
		CHECK(apmon_debuglevel_parse("3", &level) == 0 && level == 3, "debuglevel 3");
		CHECK(apmon_debuglevel_parse("4", &level) != 0, "debuglevel 4 invalid");
		CHECK(apmon_debuglevel_parse("-1", &level) != 0, "debuglevel -1 invalid");
		CHECK(apmon_debuglevel_parse("12", &level) != 0, "debuglevel 12 invalid");
		CHECK(apmon_debuglevel_parse("", &level) != 0, "empty debuglevel invalid");
	}

	apmon_format_age(12, age, sizeof(age));
	CHECK(strcmp(age, "12s") == 0, "age 12s");
	apmon_format_age(300, age, sizeof(age));
	CHECK(strcmp(age, "5m") == 0, "age 5m");
	apmon_format_age(7200, age, sizeof(age));
	CHECK(strcmp(age, "2h") == 0, "age 2h");
	apmon_format_age(200000, age, sizeof(age));
	CHECK(strcmp(age, "2d") == 0, "age 2d");

	apmon_table_init(&t, 3);
	apmon_table_add(&t, "MAC");
	apmon_table_add(&t, "STATE");
	apmon_table_add(&t, "AGE");
	apmon_table_add(&t, "aa:bb");
	apmon_table_add(&t, "stale*");
	apmon_table_add(&t, "5m");
	apmon_table_render(&t, out, sizeof(out));
	CHECK(strcmp(out, "MAC    STATE   AGE\naa:bb  stale*  5m\n") == 0, "table columns aligned");
	apmon_table_free(&t);

	CHECK(apmon_derive_keys_with_previous(TV_CHBS_PASSPHRASE, 1, &cur, &prev) == 0, "derive epoch 1 + previous");
	apmon_derive_keys(TV_CHBS_PASSPHRASE, 0, &direct);
	CHECK(prev.epoch == 0 && memcmp(prev.s2c, direct.s2c, 32) == 0, "previous epoch keys equal epoch 0 keys");
	CHECK(cur.epoch == 1 && memcmp(cur.s2c, direct.s2c, 32) != 0, "epoch 1 keys differ");
}


/*
 * Host model of apmond's logging (log.c): dedupe, append, trim at max_log_entries.
 * Regression for r10: an identical recurring message ("report accepted") was dropped
 * forever, so the log went silent after start-up.
 */
static int sim_lines;

static void sim_append(const char *path, const char *msg, int max)
{
	FILE *f = fopen(path, "a");

	if (f == NULL) {
		return;
	}
	fprintf(f, "%s\n", msg);
	fclose(f);
	sim_lines++;
	if (sim_lines > max) {
		sim_lines = apmon_trim_log(path, max);
	}
}

static void sim_log(struct apmon_dedupe *d, const char *path, const char *msg, int64_t now, int max)
{
	char summary[64];

	if (!apmon_dedupe_check(d, msg, now, summary, sizeof(summary))) {
		return;
	}
	if (summary[0] != '\0') {
		sim_append(path, summary, max);
	}
	sim_append(path, msg, max);
}

static void first_and_last(const char *path, char *first, char *last, size_t len)
{
	FILE *f = fopen(path, "r");
	char line[256];

	first[0] = '\0';
	last[0] = '\0';
	if (f == NULL) {
		return;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (first[0] == '\0') {
			snprintf(first, len, "%s", line);
		}
		snprintf(last, len, "%s", line);
	}
	fclose(f);
}

static void test_logfile(void)
{
	char path[] = "/tmp/apmon-test-log.XXXXXX";
	struct apmon_dedupe d;
	char first[256];
	char last[256];
	char msg[64];
	char expect[64];
	int fd;
	int i;
	int cycle;
	int64_t now = 1000000;
	FILE *f;

	fd = mkstemp(path);
	CHECK(fd >= 0, "log: temp file");
	if (fd < 0) {
		return;
	}
	close(fd);

	/* pre-existing file already at the limit */
	f = fopen(path, "w");
	for (i = 1; i <= 500; i++) {
		fprintf(f, "old %d\n", i);
	}
	fclose(f);
	sim_lines = apmon_count_lines(path);
	CHECK(sim_lines == 500, "log: pre-existing 500 lines counted");

	/* first trim keeps the newest 500 and drops the oldest */
	apmon_dedupe_init(&d);
	sim_log(&d, path, "start", now, 500);
	first_and_last(path, first, last, sizeof(first));
	CHECK(apmon_count_lines(path) == 500, "log: trim at 500");
	CHECK(strcmp(first, "old 2") == 0, "log: oldest line dropped");
	CHECK(strcmp(last, "start") == 0, "log: newest line kept");

	/* 2000 report cycles of 60 s with the same message and a config reload each cycle:
	   lines must keep appearing and the file must stay at 500 */
	for (cycle = 0; cycle < 2000; cycle++) {
		now += 60;
		sim_log(&d, path, "report accepted", now, 500);
		sim_log(&d, path, "report accepted", now, 500);
		if (cycle % 10 == 9) {
			/* config reload (report_cb re-reads uci): same debuglevel, nothing extra logged,
			   and the dedupe state must survive it */
			sim_log(&d, path, "report accepted", now, 500);
		}
	}
	first_and_last(path, first, last, sizeof(first));
	CHECK(apmon_count_lines(path) == 500, "log: stays at max_log_entries over 2000 cycles");
	CHECK(sim_lines == 500, "log: line counter matches file");
	CHECK(strstr(first, "old") == NULL, "log: all pre-existing lines trimmed away");
	CHECK(strcmp(last, "report accepted") == 0 || strncmp(last, "previous message repeated", 25) == 0,
	      "log: recent repeated message present");

	/* repeats are summarised at least every APMON_DEDUPE_SECONDS */
	apmon_dedupe_init(&d);
	{
		char summary[64];
		int written = 0;

		for (i = 0; i < 100; i++) {
			if (apmon_dedupe_check(&d, "same", (int64_t)i * 60, summary, sizeof(summary))) {
				written++;
			}
		}
		CHECK(written >= 100 * 60 / APMON_DEDUPE_SECONDS, "log: identical message not suppressed forever");
		CHECK(strcmp(summary, "") == 0 || strncmp(summary, "previous message repeated", 25) == 0,
		      "log: repeat summary text");
		CHECK(apmon_dedupe_check(&d, "other", 6000, summary, sizeof(summary)) == 1,
		      "log: different message written");
		CHECK(strncmp(summary, "previous message repeated", 25) == 0, "log: summary before new message");
	}

	/* distinct messages (with seq) are always written */
	apmon_dedupe_init(&d);
	for (i = 0; i < 1200; i++) {
		snprintf(msg, sizeof(msg), "report %d accepted", i);
		sim_log(&d, path, msg, now + i, 500);
	}
	snprintf(expect, sizeof(expect), "report %d accepted", 1199);
	first_and_last(path, first, last, sizeof(first));
	CHECK(strcmp(last, expect) == 0, "log: newest distinct message is last");
	CHECK(strcmp(first, "report 700 accepted") == 0, "log: oldest kept is newest-499");
	CHECK(apmon_count_lines(path) == 500, "log: 500 after distinct messages");

	/* small keep and a file without a final newline */
	f = fopen(path, "w");
	fprintf(f, "a\nb\nc");
	fclose(f);
	CHECK(apmon_trim_log(path, 2) == 2, "log: trim returns lines kept");
	first_and_last(path, first, last, sizeof(first));
	CHECK(strcmp(first, "b") == 0 && strcmp(last, "c") == 0, "log: trim without final newline");

	unlink(path);
}

/* read_log -f across trims: every new line exactly once, in order, nothing lost */
static void test_log_follow(void)
{
	char path[] = "/tmp/apmon-test-follow.XXXXXX";
	char outpath[] = "/tmp/apmon-test-follow-out.XXXXXX";
	char last[600] = "";
	char line[128];
	char expect[64];
	struct apmon_dedupe d;
	FILE *out;
	FILE *f;
	int fd;
	int i;
	int ok = 1;
	int n;

	fd = mkstemp(path);
	close(fd);
	fd = mkstemp(outpath);
	close(fd);

	f = fopen(path, "w");
	for (i = 0; i < 500; i++) {
		fprintf(f, "[%d] line\n", i);
	}
	fclose(f);
	sim_lines = 500;

	out = fopen(outpath, "w");
	CHECK(apmon_log_follow(path, last, sizeof(last), out) == 500, "follow: initial print");
	fclose(out);

	/* every append trims (file stays at 500, size roughly equal); poll after each 1..3 lines */
	out = fopen(outpath, "w");
	apmon_dedupe_init(&d);
	i = 500;
	while (i < 2000) {
		n = 1 + (i % 3);
		while (n > 0) {
			snprintf(line, sizeof(line), "[%d] %s", i, (i % 2) ? "a much longer line than before" : "x");
			sim_log(&d, path, line, i, 500);
			i++;
			n--;
		}
		apmon_log_follow(path, last, sizeof(last), out);
	}
	fclose(out);
	CHECK(apmon_count_lines(path) == 500, "follow: file stays at 500");

	f = fopen(outpath, "r");
	i = 500;
	while (f != NULL && fgets(line, sizeof(line), f) != NULL) {
		snprintf(expect, sizeof(expect), "[%d] ", i);
		if (strncmp(line, expect, strlen(expect)) != 0) {
			ok = 0;
		}
		i++;
	}
	if (f != NULL) {
		fclose(f);
	}
	CHECK(ok && i == 2000, "follow: all 1500 lines once and in order across trims");

	unlink(path);
	unlink(outpath);
}

/* r13 identity: file hash, restart_needed, short hashes */
static void test_identity(void)
{
	char path[] = "/tmp/apmon-test-hash.XXXXXX";
	char a[65];
	char b[65];
	char shorth[9];
	FILE *f;
	int fd;

	fd = mkstemp(path);
	close(fd);
	f = fopen(path, "w");
	fputs("abc", f);
	fclose(f);
	CHECK(apmon_sha256_file(path, a) == 0, "identity: hash a file");
	CHECK(strcmp(a, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
	      "identity: sha256(abc) as sha256sum");

	/* same file again: same hash, no restart */
	CHECK(apmon_sha256_file(path, b) == 0 && strcmp(a, b) == 0, "identity: hash is stable");
	CHECK(apmon_restart_needed(a, b) == 0, "identity: same hash -> no restart");

	/* binary replaced on disk (one byte appended) -> restart needed */
	f = fopen(path, "a");
	fputc('\n', f);
	fclose(f);
	CHECK(apmon_sha256_file(path, b) == 0 && strcmp(a, b) != 0, "identity: changed file, new hash");
	CHECK(apmon_restart_needed(a, b) == 1, "identity: different hash -> restart needed");

	/* unknown -> null */
	CHECK(apmon_restart_needed(a, "") == -1, "identity: installed unknown -> null");
	CHECK(apmon_restart_needed(NULL, b) == -1, "identity: running unknown (older beta) -> null");
	CHECK(apmon_sha256_file("/nonexistent/apmond", b) == -1 && b[0] == '\0', "identity: missing file");

	apmon_short_hash(a, shorth);
	CHECK(strcmp(shorth, "ba7816bf") == 0, "identity: 8 character short hash");
	apmon_short_hash(NULL, shorth);
	CHECK(strcmp(shorth, "-") == 0, "identity: short hash of null is -");

	unlink(path);
}

/* r15 node id: factory MAC in 1.x get_factory_mac order, from a fake root tree */
static void put(const char *root, const char *rel, const void *data, size_t len)
{
	char path[512];
	char cmd[600];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", root, rel);
	snprintf(cmd, sizeof(cmd), "mkdir -p \"$(dirname '%s')\"", path);
	if (system(cmd) != 0) {
		return;
	}
	f = fopen(path, "wb");
	fwrite(data, 1, len, f);
	fclose(f);
}

static void put_if(const char *root, const char *dev, const char *mac, int ifindex, int type)
{
	char rel[128];
	char text[32];

	snprintf(rel, sizeof(rel), "sys/class/net/%s/address", dev);
	put(root, rel, mac, strlen(mac));
	snprintf(rel, sizeof(rel), "sys/class/net/%s/ifindex", dev);
	snprintf(text, sizeof(text), "%d\n", ifindex);
	put(root, rel, text, strlen(text));
	snprintf(rel, sizeof(rel), "sys/class/net/%s/type", dev);
	snprintf(text, sizeof(text), "%d\n", type);
	put(root, rel, text, strlen(text));
}

static int id_is(const char *root, const char *wan, const char *want, const char *want_src)
{
	uint8_t id[APMON_ID_LEN];
	char mac[18];
	char src[96];

	if (apmon_factory_mac(root, wan, "br-lan", id, src, sizeof(src)) != 0) {
		return want == NULL;
	}
	apmon_mac_format(id, mac);
	if (want == NULL) {
		return 0;
	}
	if (strcmp(mac, want) != 0) {
		printf("  got %s from %s\n", mac, src);
		return 0;
	}
	return strstr(src, want_src) != NULL;
}

static void test_factory_mac(void)
{
	char root[] = "/tmp/apmon-test-root.XXXXXX";
	char cmd[128];
	const uint8_t dtmac[6] = { 0x94, 0x83, 0xc4, 0xa2, 0x8e, 0xc9 };
	const uint8_t zero[6] = { 0 };
	const char *board = "{\n\t\"model\": { \"id\": \"glinet,gl-mt6000\" },\n\t\"system\": {\n\t\t\"label_macaddr\": \"94:83:c4:52:68:73\"\n\t}\n}\n";
	const char *dtpath = "/soc/ethernet@15100000/mac@1";

	if (mkdtemp(root) == NULL) {
		CHECK(0, "factory mac: temp dir");
		return;
	}
	CHECK(id_is(root, "", NULL, NULL), "factory mac: nothing at all -> error");

	/* 5. only br-lan (eg x86 with no ether type): device MAC */
	put_if(root, "br-lan", "96:83:c4:a3:8e:c9\n", 9, 1);
	CHECK(id_is(root, "", "96:83:c4:a3:8e:c9", "first ethernet interface br-lan"),
	      "factory mac: br-lan is the only ether interface");
	put(root, "sys/class/net/br-lan/type", "772\n", 4);
	CHECK(id_is(root, "", "96:83:c4:a3:8e:c9", "device br-lan"), "factory mac: last resort option device");

	/* 4. first ether interface by ifindex, skipping non-ether and zero MACs */
	put_if(root, "zz0", "00:00:00:00:00:00\n", 2, 1);
	put_if(root, "wlan9", "02:00:00:00:00:09\n", 3, 801);
	put_if(root, "end5", "94:83:c4:00:00:05\n", 5, 1);
	put_if(root, "end4", "94:83:c4:00:00:04\n", 4, 1);
	CHECK(id_is(root, "", "94:83:c4:00:00:04", "first ethernet interface end4"),
	      "factory mac: lowest ifindex ether, zero MAC skipped");

	/* 3. eth1 eth0 lan0 lan1, in that order */
	put_if(root, "lan1", "94:83:c4:00:01:01\n", 20, 1);
	CHECK(id_is(root, "", "94:83:c4:00:01:01", "fallback interface lan1"), "factory mac: lan1");
	put_if(root, "eth0", "94:83:c4:a2:8e:cb\n", 21, 1);
	CHECK(id_is(root, "", "94:83:c4:a2:8e:cb", "fallback interface eth0"), "factory mac: eth0 before lan1");
	put_if(root, "eth1", "94:83:c4:a2:8e:ca\n", 22, 1);
	CHECK(id_is(root, "", "94:83:c4:a2:8e:ca", "fallback interface eth1"), "factory mac: eth1 before eth0");

	/* 2. network.wan.device; missing wan device falls through */
	put_if(root, "wan", "94:83:c4:a2:8e:c8\n", 23, 1);
	CHECK(id_is(root, "wan", "94:83:c4:a2:8e:c8", "network.wan.device wan"), "factory mac: wan device first");
	CHECK(id_is(root, "nosuch", "94:83:c4:a2:8e:ca", "fallback interface eth1"), "factory mac: missing wan device");
	CHECK(id_is(root, "../x", "94:83:c4:a2:8e:ca", "fallback interface eth1"), "factory mac: no path in wan device");

	/* 1b. board.json label_macaddr */
	put(root, "etc/board.json", board, strlen(board));
	CHECK(id_is(root, "wan", "94:83:c4:52:68:73", "board.json"), "factory mac: board.json label_macaddr");

	/* 1a. device tree: label-mac-device, local-mac-address, then mac-address wins; zero ignored */
	put(root, "proc/device-tree/aliases/label-mac-device", dtpath, strlen(dtpath) + 1);
	CHECK(id_is(root, "wan", "94:83:c4:52:68:73", "board.json"), "factory mac: DT node without a MAC");
	snprintf(cmd, sizeof(cmd), "proc/device-tree%s/mac-address", dtpath);
	put(root, cmd, zero, 6);
	CHECK(id_is(root, "wan", "94:83:c4:52:68:73", "board.json"), "factory mac: DT zero MAC ignored");
	snprintf(cmd, sizeof(cmd), "proc/device-tree%s/local-mac-address", dtpath);
	put(root, cmd, dtmac, 6);
	CHECK(id_is(root, "wan", "94:83:c4:a2:8e:c9", "device tree"), "factory mac: DT local-mac-address");
	snprintf(cmd, sizeof(cmd), "proc/device-tree%s/mac-address", dtpath);
	put(root, cmd, "\x94\x83\xc4\x2e\xf9\xd1", 6);
	CHECK(id_is(root, "wan", "94:83:c4:2e:f9:d1", "device tree"), "factory mac: DT mac-address first");

	/* br-lan MAC changed (mesh11sd): id unchanged */
	put(root, "sys/class/net/br-lan/address", "96:83:c4:ff:ff:ff\n", 18);
	CHECK(id_is(root, "wan", "94:83:c4:2e:f9:d1", "device tree"), "factory mac: br-lan MAC change does not matter");

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
	if (system(cmd) != 0) {
		CHECK(0, "factory mac: clean up");
	}
}

int main(void)
{
	test_factory_mac();
	test_identity();
	test_logfile();
	test_log_follow();
	test_rfc5869();
	test_keys(TV_DEFAULT_PASSPHRASE, TV_DEFAULT_IKM, TV_DEFAULT_K_S2C, TV_DEFAULT_K_C2S, "built-in default");
	test_keys(TV_CHBS_PASSPHRASE, TV_CHBS_IKM, TV_CHBS_K_S2C, TV_CHBS_K_C2S, "correct horse");
	test_vector_message();
	test_negative();
	test_round_trip_and_replay();
	test_json();
	test_extra();

	printf("\n%d passed, %d failed\n", passes, failures);
	if (failures > 0) {
		return 1;
	}
	return 0;
}
