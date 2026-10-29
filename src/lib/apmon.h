/*
 * libapmon - apmon protocol 2 (see docs/PROTOCOL.md)
 *
 * This file is part of apmon. SPDX-License-Identifier: GPL-2.0-only
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define APMON_MAGIC "APM2"
#define APMON_VERSION 2
#define APMON_HEADER_LEN 48
#define APMON_NONCE_LEN 12
#define APMON_TAG_LEN 16
#define APMON_KEY_LEN 32
#define APMON_ID_LEN 6

#define APMON_PBKDF2_SALT "apmon/2 pbkdf2"
#define APMON_PBKDF2_ITERATIONS 50000
#define APMON_HKDF_SALT "apmon/2 salt"
#define APMON_INFO_S2C "apmon/2 s2c"
#define APMON_INFO_C2S "apmon/2 c2s"

#define APMON_DEFAULT_PORT 2468
#define APMON_PATH_REPORT "/apmon/v2/report"
#define APMON_PATH_TIME "/apmon/v2/time"
#define APMON_CONTENT_TYPE "application/vnd.apmon.v2"
#define APMON_DEFAULT_MAX_MESSAGE 262144

/* Message types */
#define APMON_TYPE_REPORT 0x01
#define APMON_TYPE_TIME_REQ 0x02
#define APMON_TYPE_ACK 0x81
#define APMON_TYPE_TIME_RESP 0x82
#define APMON_TYPE_ERROR 0x8f

/* Header flags */
#define APMON_FLAG_CLOCK_FROM_COLLECTOR 0x0001
#define APMON_FLAG_DEFAULT_PASSPHRASE 0x0002
#define APMON_FLAGS_KNOWN 0x0003

/* Results of apmon_open() and the replay check, mapped to HTTP status codes by the collector */
enum apmon_result {
	APMON_OK = 0,
	APMON_ERR_MALFORMED,     /* 400 */
	APMON_ERR_AUTH,          /* 401 */
	APMON_ERR_VERSION,       /* 426 */
	APMON_ERR_TIME,          /* 409 */
	APMON_ERR_REPLAY,        /* 409 */
	APMON_ERR_NOMEM,
	APMON_ERR_CRYPTO,
};

struct apmon_keys {
	uint32_t epoch;
	uint8_t s2c[APMON_KEY_LEN];
	uint8_t c2s[APMON_KEY_LEN];
};

struct apmon_header {
	uint8_t version;
	uint8_t type;
	uint16_t flags;
	uint32_t key_epoch;
	uint8_t sender_id[APMON_ID_LEN];
	uint64_t timestamp_ms;
	uint32_t seq;
	uint8_t nonce[APMON_NONCE_LEN];
	uint32_t ct_len;
};

/* crypto.c (backend selected at build time; mbedtls for now) */
int apmon_random(void *buf, size_t len);
int apmon_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
			unsigned int iterations, uint8_t *out, size_t out_len);
int apmon_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
		      uint8_t out[32]);
int apmon_gcm_seal(const uint8_t key[APMON_KEY_LEN], const uint8_t nonce[APMON_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct_tag);
int apmon_gcm_open(const uint8_t key[APMON_KEY_LEN], const uint8_t nonce[APMON_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *ct_tag, size_t ct_tag_len, uint8_t *pt);

/* kdf.c */
int apmon_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
		       uint8_t prk[32]);
int apmon_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);
int apmon_derive_keys(const char *passphrase, uint32_t epoch, struct apmon_keys *keys);

/* envelope.c */
void apmon_header_encode(const struct apmon_header *h, uint8_t out[APMON_HEADER_LEN]);
enum apmon_result apmon_header_decode(const uint8_t *buf, size_t len, struct apmon_header *h);

/*
 * Seal: fills in nonce (random) and ct_len, writes header + ciphertext + tag to *out (malloc'd).
 * Open: checks the header and tag, returns the plaintext as a malloc'd NUL-terminated string.
 */
enum apmon_result apmon_seal(const uint8_t key[APMON_KEY_LEN], struct apmon_header *h,
			     const char *plaintext, size_t pt_len, uint8_t **out, size_t *out_len);
enum apmon_result apmon_seal_with_nonce(const uint8_t key[APMON_KEY_LEN], struct apmon_header *h,
					const char *plaintext, size_t pt_len, uint8_t **out, size_t *out_len);
enum apmon_result apmon_open(const uint8_t key[APMON_KEY_LEN], const uint8_t *msg, size_t msg_len,
			     struct apmon_header *h, char **plaintext, size_t *pt_len);

/* replay.c */
struct apmon_replay_entry {
	uint8_t sender_id[APMON_ID_LEN];
	uint8_t nonce[APMON_NONCE_LEN];
	uint64_t expires_ms;
};

struct apmon_replay {
	struct apmon_replay_entry *entries;
	size_t size;
	uint64_t max_skew_ms;
};

int apmon_replay_init(struct apmon_replay *r, size_t size, uint64_t max_skew_ms);
void apmon_replay_free(struct apmon_replay *r);
enum apmon_result apmon_replay_check(struct apmon_replay *r, const struct apmon_header *h, uint64_t now_ms,
				     int check_window);

/* util.c */
uint64_t apmon_now_ms(void);
uint64_t apmon_monotonic_ms(void);
void apmon_hex_encode(const uint8_t *in, size_t len, char *out);
int apmon_hex_decode(const char *in, uint8_t *out, size_t out_len);
void apmon_mac_format(const uint8_t id[APMON_ID_LEN], char out[18]);
int apmon_mac_parse(const char *s, uint8_t id[APMON_ID_LEN]);

/* json.c - small JSON writer for building payloads */
struct apmon_json {
	char *buf;
	size_t len;
	size_t cap;
	int need_comma;
	int failed;
};

void apmon_json_init(struct apmon_json *j);
void apmon_json_free(struct apmon_json *j);
void apmon_json_open_object(struct apmon_json *j, const char *key);
void apmon_json_close_object(struct apmon_json *j);
void apmon_json_open_array(struct apmon_json *j, const char *key);
void apmon_json_close_array(struct apmon_json *j);
void apmon_json_string(struct apmon_json *j, const char *key, const char *value);
void apmon_json_int(struct apmon_json *j, const char *key, int64_t value);
void apmon_json_double(struct apmon_json *j, const char *key, double value);
void apmon_json_bool(struct apmon_json *j, const char *key, int value);
void apmon_json_null(struct apmon_json *j, const char *key);
void apmon_json_raw(struct apmon_json *j, const char *key, const char *raw);

/* extra.c */
#define APMON_BLOCK_NAME_MAX 32
#define APMON_BLOCK_DATA_MAX 16384
#define APMON_TABLE_MAX_COLUMNS 16

struct apmon_table {
	char **cells;
	size_t count;
	size_t cap;
	int columns;
};

int apmon_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
int apmon_sha256_file(const char *path, char hex[65]);
int apmon_restart_needed(const char *running_sha256, const char *installed_sha256);
void apmon_short_hash(const char *hash, char out[9]);
int apmon_ula_prefix(const char *passphrase, uint8_t out[8]);
void apmon_eui64_iid(const uint8_t mac[APMON_ID_LEN], uint8_t out[8]);
int apmon_block_name_valid(const char *name);
void apmon_format_age(int64_t seconds, char *out, size_t out_len);
/* Node display order (1.x show_ap_data): the collector first, then hostname, then id */
int apmon_node_cmp(int collector_a, const char *host_a, const char *id_a, int collector_b, const char *host_b,
		   const char *id_b);

/* Pretty JSON writer (CLI output): two space indent, "key": value, {} and [] when empty */
#define APMON_PRETTY_DEPTH 32

struct apmon_pretty {
	char *buf;
	size_t len;
	size_t cap;
	int depth;
	int failed;
	int count[APMON_PRETTY_DEPTH];
	int is_object[APMON_PRETTY_DEPTH];
};

void apmon_pretty_init(struct apmon_pretty *p);
void apmon_pretty_free(struct apmon_pretty *p);
void apmon_pretty_open_object(struct apmon_pretty *p, const char *key);
void apmon_pretty_open_array(struct apmon_pretty *p, const char *key);
void apmon_pretty_close(struct apmon_pretty *p);
void apmon_pretty_string(struct apmon_pretty *p, const char *key, const char *value);
void apmon_pretty_raw(struct apmon_pretty *p, const char *key, const char *value);
void apmon_pretty_int(struct apmon_pretty *p, const char *key, long long value);
void apmon_pretty_double(struct apmon_pretty *p, const char *key, double value);
void apmon_pretty_bool(struct apmon_pretty *p, const char *key, int value);
const char *apmon_pretty_text(struct apmon_pretty *p);

/* Bridge VLAN flags as in linux/if_bridge.h */
#define APMON_BRVLAN_PVID 0x2
#define APMON_BRVLAN_UNTAGGED 0x4

int apmon_port_access_vlan(const uint16_t *flags, const uint16_t *vids, int count);
int apmon_vlan_from_name(const char *ifname);
int apmon_client_ordered_field(const char *name);
int apmon_debuglevel_parse(const char *text, int *level);
void apmon_format_date(int64_t unix_s, char *out, size_t len);

/* Log file helpers (logfile.c) */
#define APMON_DEDUPE_SECONDS 300

struct apmon_dedupe {
	char last[512];
	int have_last;
	unsigned int repeats;
	int64_t written_s;
};

void apmon_dedupe_init(struct apmon_dedupe *d);
int apmon_dedupe_check(struct apmon_dedupe *d, const char *msg, int64_t now_s, char *summary, size_t len);
int apmon_count_lines(const char *path);
int apmon_trim_log(const char *path, int keep);
int apmon_log_follow(const char *path, char *last, size_t lastlen, FILE *out);

void apmon_table_init(struct apmon_table *t, int columns);
void apmon_table_add(struct apmon_table *t, const char *cell);
size_t apmon_table_render(const struct apmon_table *t, char *out, size_t out_len);
void apmon_table_free(struct apmon_table *t);

/* kdf.c: keys for the current and the previous epoch from one PBKDF2 run */
int apmon_derive_keys_with_previous(const char *passphrase, uint32_t epoch, struct apmon_keys *current,
				    struct apmon_keys *previous);
