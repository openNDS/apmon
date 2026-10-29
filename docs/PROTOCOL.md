# apmon wire protocol, version 2

Status: **draft for review** (2.0.0beta). This is the protocol spoken by apmond 2.x and libapmon.
It is a clean design: it does not interoperate with apmond 1.x or with the script apmond built into mesh11sd.

Key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

| Role | Who | Does |
|---|---|---|
| **Sender** | every AP node running apmond (the collector also reports about itself, over loopback) | builds a report every `interval` seconds, encrypts it, POSTs it to the collector |
| **Collector** | the node with the upstream gateway (auto-detected, as in 1.x), reachable at `<ula_prefix>:<ula_subnet>::1` | listens with libmicrohttpd, authenticates and decrypts reports, stores the latest state per node, exposes it on ubus |

One report = one HTTP POST = one encrypted message. There is no chunking, no hex encoding and no TLS.
Confidentiality, integrity and authenticity come from AES-256-GCM over the payload, keyed from the shared passphrase.

## 2. Transport

| Item | Value |
|---|---|
| Protocol | HTTP/1.1, plain TCP, IPv6 (ULA) preferred, IPv4 allowed |
| Port | **TCP 2468** by default (uci `apmond.setup.port`). Chosen to be clear of 80/443 (uhttpd), 2050 (openNDS) and other common OpenWrt services |
| Report path | `POST /apmon/v2/report` |
| Time sync path | `POST /apmon/v2/time` |
| Request `Content-Type` | `application/vnd.apmon.v2` (anything else: 415) |
| Response `Content-Type` | `application/vnd.apmon.v2` when the body is an encrypted message; no body otherwise |
| Max request body | 262144 bytes default (uci `max_message_size`); larger, or a missing/oversized `Content-Length`: 413. The collector MUST stop reading at the limit |
| Timeouts | sender: 10 s connect+response; collector: 15 s per connection, max 32 concurrent connections |
| Other methods / paths | 405 / 404, no body |

The listener binds only to the collector ULA (and optionally the LAN IPv4) — never the WAN.

### Status codes

| Code | Meaning | Body |
|---|---|---|
| 200 | accepted | encrypted `ack` (section 7) |
| 400 | malformed envelope (bad magic, length mismatch, reserved bits set) | none |
| 401 | authentication failed (GCM tag invalid, unknown key epoch) | none |
| 409 | authenticated but rejected: timestamp outside window, replayed nonce or sequence | encrypted `error` carrying `collector_time` so the sender can resync |
| 413 / 415 / 404 / 405 | as above | none |
| 426 | unsupported protocol `version` byte | none |
| 503 | this node is not (currently) the collector, or it is overloaded | none |

Nothing unauthenticated ever gets an encrypted or informative body, so a probe learns only "an apmon v2 collector is here".

## 3. Message envelope

**Decision: a fixed 48-byte binary header followed by AES-256-GCM ciphertext of a UTF-8 JSON document.**

Why: the header must be parsed *before* decryption (to pick a key and check replay cheaply), so it should be fixed-size and trivial to parse safely in C — no JSON parser touches unauthenticated input. The plaintext is JSON because it is easy to extend, easy to debug, matches the 1.x reports, and libubox `blobmsg_json` turns it straight into ubus data. Whole header = AAD, so every header byte is authenticated.

All integers are unsigned, **big-endian**.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `APM2` (`41 50 4d 32`) |
| 4 | 1 | `version` | `2` |
| 5 | 1 | `type` | see table below |
| 6 | 2 | `flags` | bit 0 `CLOCK_FROM_COLLECTOR`: sender's timestamp is collector-referenced (section 5); bit 1 `DEFAULT_PASSPHRASE`: sender uses the built-in passphrase; bits 2–15 reserved, MUST be 0 (else 400) |
| 8 | 4 | `key_epoch` | key generation, uci `key_epoch` (default 0), see section 4 |
| 12 | 6 | `sender_id` | the node's id: MAC of `option device` (br-lan), as 1.x `device_mac`. For collector→sender messages, the collector's id |
| 18 | 2 | `reserved` | MUST be 0 |
| 20 | 8 | `timestamp` | Unix time in **milliseconds** when the message was sealed |
| 28 | 4 | `seq` | per-sender counter, +1 per message, starts at a random value at daemon start, wraps |
| 32 | 12 | `nonce` | GCM IV, 96 bits from the system CSPRNG (`getrandom()`), fresh for every message |
| 44 | 4 | `ct_len` | length of ciphertext **including** the 16-byte tag. MUST equal body length − 48 |
| 48 | `ct_len` | ciphertext ‖ tag | AES-256-GCM, 16-byte tag appended |

**AAD** = the 48 header bytes exactly as sent. **IV** = `nonce`.

| `type` | Direction | Plaintext |
|---|---|---|
| `0x01` REPORT | sender → collector | report (section 6) |
| `0x02` TIME_REQ | sender → collector | `{"v":2,"type":"time_req"}` |
| `0x81` ACK | collector → sender | ack (section 7) |
| `0x82` TIME_RESP | collector → sender | time response (section 5) |
| `0x8F` ERROR | collector → sender | error (section 7) |

A receiver MUST reject a `type` it does not expect in that direction or on that path.

## 4. Key derivation

Input keying material is the shared passphrase, `apmond.setup.apmon_seed` (same uci option as 1.x, same on every node).
If unset, the built-in default `--__` is used (as 1.x and mesh11sd), `DEFAULT_PASSPHRASE` is set in every header, and apmond logs the existing periodic notice.

HKDF-SHA256 (RFC 5869), implemented on mbedtls HMAC-SHA256 (`MBEDTLS_HKDF_C` is not enabled in OpenWrt's mbedtls):

```
IKM   = apmon_seed as raw UTF-8 bytes (no trailing newline)
PRK   = HKDF-Extract(salt = "apmon/2 salt", IKM)
K_s2c = HKDF-Expand(PRK, info = "apmon/2 s2c" || u32be(key_epoch), L = 32)   # sender -> collector
K_c2s = HKDF-Expand(PRK, info = "apmon/2 c2s" || u32be(key_epoch), L = 32)   # collector -> sender
```

(strings are ASCII, no terminator). Separate keys per direction mean a collector reply can never be replayed to the collector as a report, even before the `type` check.

`key_epoch` allows a passphrase change without a flag day: the collector MAY hold keys for the current and previous epoch (uci `accept_previous_epoch`, default off). The ULA prefix and subnet continue to be derived from `sha256(apmon_seed)` exactly as in 1.x, so addressing is unchanged; that derivation is independent of these keys.

## 5. Time, replay window and nodes without a clock

Collector rules for every REPORT (after the GCM tag verifies — never before):

1. **Window:** `|timestamp − collector_now| ≤ max_skew` (uci `max_age`, default **120 s**). Otherwise 409.
2. **Nonce cache:** keep each accepted `(sender_id, nonce)` for `2 × max_skew`; a repeat is 409. Memory: one entry per accepted message, bounded by nodes × (240 s / interval).
3. **Sequence:** per sender keep the last accepted `seq`; accept only `seq` "newer" in serial-number arithmetic (RFC 1982, 32-bit), or any `seq` when the previous accepted message is older than `max_skew` (daemon restart). Otherwise 409.

(1)+(2) alone are sufficient against replay; (3) also rejects reordering within the window.

**Routers often boot without RTC or NTP.** So senders never rely on their own wall clock:

- At start, after a 409, and every 6 h, the sender sends a `TIME_REQ` to `/apmon/v2/time`. The TIME_REQ is checked for authenticity and nonce reuse **but not** for the time window.
- The collector replies `TIME_RESP`, plaintext `{"v":2,"type":"time_resp","collector_time":<ms>,"echo_nonce":"<hex of request nonce>"}`. The sender MUST check `echo_nonce` (that binds the answer to its own fresh request, so an old answer cannot be replayed to it).
- The sender stores `offset = collector_time − monotonic_now_ms` (CLOCK_MONOTONIC, unaffected by NTP steps) and stamps every message with `monotonic_now_ms + offset`, setting `CLOCK_FROM_COLLECTOR`.
- The collector is the single time reference and uses its own `CLOCK_REALTIME`. If the collector's clock steps (NTP arriving late), senders get 409 once, resync, and carry on. Every ACK also carries `collector_time`, so senders track drift for free.

The collector reports about itself through the same code path over loopback.

## 6. Report payload (REPORT plaintext)

UTF-8 JSON, one object, compact. Unknown fields MUST be ignored; missing optional fields mean "unknown". Times are Unix ms on the collector-referenced clock; durations are ms. Fields come from what 1.x reports (`node_status`, AP/station blocks, ethernet clients).

```json
{
  "v": 2,
  "type": "report",
  "report_time": 1793270400000,
  "interval": 30,
  "node": {
    "id": "94:83:c4:a1:b2:c3",
    "factory_mac": "94:83:c4:a1:b2:c0",
    "hostname": "ap1",
    "model": "GL.iNet GL-MT300N-V2",
    "apmond_version": "2.0.0",
    "openwrt_release": "25.12.0",
    "role": "peer",
    "uptime": 3600,
    "load": [0.12, 0.20, 0.18],
    "free_ram_kb": 21000,
    "free_flash_kb": 5000,
    "cpu_temperature_c": null,
    "cpu_frequency_mhz": 580,
    "node_ula": "fd12:3456:789a:1b2c::94:83c4:a1b2:c3",
    "ipv4_addresses": ["192.168.8.2/24"],
    "default_passphrase": false
  },
  "radios": [
    { "phy": "phy0", "band": "2g", "channel": 6, "width_mhz": 20, "max_width_mhz": 40, "txpower_dbm": 20,
      "aps": [ { "ifname": "phy0-ap0", "ssid": "Home", "bssid": "94:83:c4:a1:b2:c4", "vlan": null } ] }
  ],
  "clients": [
    { "mac": "aa:bb:cc:dd:ee:ff", "kind": "wifi", "ap": "phy0-ap0", "vlan": null,
      "signal_avg_dbm": -58, "ack_signal_avg_dbm": -60,
      "tx_bitrate_kbps": 72200, "rx_bitrate_kbps": 65000,
      "tx_bytes": 123456, "rx_bytes": 654321, "tx_retries": 3,
      "connected_ms": 1200000, "inactive_ms": 1500, "last_seen": 1793270398500 },
    { "mac": "11:22:33:44:55:66", "kind": "wired", "bridge": "br-lan", "port": "lan1", "vlan": 10,
      "speed_mbps": 100, "last_seen": 1793270400000 }
  ],
  "blocks": {}
}
```

| Object | Required fields | Notes |
|---|---|---|
| top | `v`, `type`, `report_time`, `node`, `clients` | `radios` omitted on wired-only nodes |
| `node` | `id`, `apmond_version`, `uptime` | rest optional |
| client | `mac`, `kind` (`wifi`/`wired`), `last_seen` | `last_seen` = `report_time − inactive_ms` for Wi-Fi; for wired, the time the FDB entry was last refreshed (`report_time − fdb age`) |
| `blocks` | — | named extension objects added by other programs via the ubus `add_block` method (e.g. a future mesh11sd `"mesh": {...}`). Each ≤ 16 KiB |

**Stale clients (Rob's "last seen" tweak):** each client carries its own `last_seen`. The collector keeps a client that has dropped out of its node's report as `"state":"stale"` with its last `last_seen` until `client_stale_timeout` (uci, default 600 s) has passed, then removes it. A client seen on another node moves there immediately (roaming), keeping the newest `last_seen`.

## 7. Collector responses

On 200 the body is an encrypted `ACK` (key `K_c2s`, `sender_id` = collector id, fresh nonce):

```json
{"v":2,"type":"ack","status":"ok","collector_time":1793270400250,"echo_nonce":"000102030405060708090a0b","interval":30}
```

| Field | Meaning |
|---|---|
| `echo_nonce` | nonce of the request being answered; sender MUST check it |
| `collector_time` | for drift tracking (section 5) |
| `interval` | OPTIONAL hint: the collector's preferred report interval; sender MAY adopt it within [10, 3600] s |
| `config` | OPTIONAL object of further hints, reserved for later; unknown keys ignored |

On 409 the body is an encrypted `ERROR`: `{"v":2,"type":"error","code":"time"|"replay","collector_time":...,"echo_nonce":"..."}`. On `time` the sender resyncs (section 5) and resends once with a new nonce and `seq`.

A sender MUST NOT trust an ACK/ERROR whose tag fails or whose `echo_nonce` does not match; it treats that as no response and retries at the next interval (no immediate retry storm). Senders back off on 401/503 (double up to 5 min).

## 8. Versioning and extensibility

- `magic` stays `APM2` for this envelope; `version` is bumped only for an incompatible envelope or crypto change (collector answers 426).
- New header semantics use reserved `flags` bits, which receivers reject until they understand them.
- Payload evolution is additive JSON: new optional fields, `v` stays 2. A breaking payload change bumps `v` and the path (`/apmon/v3/...`).
- New crypto backends (openssl, wolfssl builds) MUST produce byte-identical output; the test vectors are the conformance check.

## 9. What the collector stores and exposes

Runtime state lives in RAM (`/var/run/apmond`), latest report per node, plus per-client state. Optional history file under `log_mountpoint` as in 1.x.

ubus object **`apmond`** (used by luci-app-apmond and the `apmond` CLI, which becomes a thin ubus client):

| Method | Args | Returns |
|---|---|---|
| `status` | — | role, collector address, port, version, `default_passphrase`, key epoch, counters (accepted, 401, 409, 413), node count |
| `nodes` | — | array of nodes: `id`, hostname, `last_report`, `age_s`, `state` (`ok`/`late`/`lost`), client count, `default_passphrase` |
| `node` | `id` | the node's last full report plus collector metadata (`received`, source address) |
| `clients` | `node`? , `include_stale`? | flattened client list with `node`, `state` (`active`/`stale`), `last_seen` |
| `client` | `mac` | one client, with node history (last N roams) |
| `add_block` | `name`, `data` | sender side: attach/replace an extension block in this node's reports |
| `remove_block` | `name` | sender side |
| `forget` | `id` | drop a node and its clients |

ubus events: `apmond.node.new`, `apmond.node.lost`, `apmond.client.roam`. ubus ACLs restrict write methods to root.

## 10. Security considerations

- **Protected:** report contents (confidentiality), integrity and origin from a key holder, freshness (window + nonce + seq). Any node holding the passphrase can impersonate any other node id — membership is the passphrase, as in 1.x.
- **Not protected (metadata):** who talks to whom, message size and timing, and the cleartext header: sender MAC, timestamp, sequence, key epoch and the default-passphrase flag. The MAC is already visible on the LAN anyway.
- **No forward secrecy:** anyone who later learns the passphrase can decrypt captured traffic. Accepted for AP monitoring data; rotate with `key_epoch` if a passphrase leaks.
- **Low-entropy passphrases:** HKDF does not slow down guessing; a captured message allows offline dictionary attacks on a weak passphrase. The default `--__` gives **no** security at all; it exists only to work out of the box, and both ends flag and log it. LuCI should show it prominently.
- **Nonces:** random 96-bit per message. At 1 message / 10 s per node, collision probability is negligible for decades; never use a counter-derived or fixed IV in production. Test vectors use fixed nonces **only** for testing.
- **Parsing:** only the fixed header is parsed before authentication; JSON is parsed only after the tag verifies, with size and depth limits (depth ≤ 8, ≤ 512 clients per report).
- **Exposure:** the listener binds to the ULA/LAN only; the firewall should not open TCP 2468 on WAN. Compared with 1.x, uhttpd, px5g and certificates go away. Note that 1.x TLS did not stop an active attacker either (`--no-check-certificate`).
- **No downgrade:** there is no unencrypted or weaker mode.

## 11. Test vectors

Generated by `tests/vectors/gen_vectors.py` (python3-cryptography 43). Includes a self-check against RFC 5869 test case A.1. All hex.

### Keys, key_epoch = 0

| Passphrase | PRK | K_s2c | K_c2s |
|---|---|---|---|
| `--__` (default) | `ec3905a56147edab713d982a329b93524a91e711f258e895c68da6b2f30ceb89` | `fc9eb2c32146b28f6e4a89a819a5ae75dc22399e4fec2948d3224978e1c43f2a` | `c75d165ba959a88df4b60d07ae1f3633ad37e56be1df618fc8c2a936f9962cb2` |
| `correct horse battery staple` | `89ae5cf88181245b7047eeeb07edb38875b37e09c487cf0fb13e247f8a4e6a44` | `ba0202623a777230cecfd27ce2217fbd4e4f293f57ce12424a6a4b10797fd4aa` | `583c67d01ed67a4a05f2c50bb4c784baa013952cfc045307a61bca13690318dd` |

### REPORT (passphrase `correct horse battery staple`, K_s2c)

sender_id `94:83:c4:a1:b2:c3`, flags 0, epoch 0, timestamp 1793270400000, seq 42, nonce `000102030405060708090a0b`.

Plaintext (113 bytes, so ct_len = 129):
```
{"v":2,"type":"report","node":{"id":"94:83:c4:a1:b2:c3","hostname":"ap1","uptime":3600},"radios":[],"clients":[]}
```
Header (= AAD):
```
41504d3202010000000000009483c4a1b2c30000000001a1873ec4000000002a000102030405060708090a0b00000081
```
Full message (header ‖ ciphertext ‖ tag):
```
41504d3202010000000000009483c4a1b2c30000000001a1873ec4000000002a000102030405060708090a0b00000081
bd1108221a083c95c29fedf3f40f9202b6d6f7fa22baadf2a42783aab2283136a1eb40e4465dce0a7f8c8d5f075958c8
e98b79495b66549a62637325a1621bc4717ecaa4e334e09257138c6676cf093ff0c78798948444af2bd669cbe1dc921e
98cf7510be204280b85aefb732cba93bc670e9861df1bcd81f8c2e197b24285e98
```

### ACK (K_c2s)

collector id `94:83:c4:00:00:01`, timestamp 1793270400250, seq 7, nonce `0b0a09080706050403020100`.

Plaintext:
```
{"v":2,"type":"ack","status":"ok","collector_time":1793270400250,"echo_nonce":"000102030405060708090a0b","interval":30}
```
Full message:
```
41504d3202810000000000009483c40000010000000001a1873ec4fa000000070b0a0908070605040302010000000087
f798093c53ff01d7dd6f4baca3dbdd7e4543d6426c3dea795bb4c090ede318fc977b39bd445600ba5579a66e8ecdba2a
9b3603c0b3cdf2239aeaba41a45b2ae89263872da97f21b3d15868c115a1807c6e42cc49397a7368d4ddd5055349d7de
cbf66da65f1d76021232309ec2a73e9b362722ac6d53b9c931a605de85bd0b921fe597a964294f
```

Negative tests implementations MUST pass: flip any header byte → 401 (tag fails); flip any ciphertext byte → 401; same message twice → 2nd is 409; timestamp ±121 s → 409; `ct_len` ≠ body − 48 → 400; reserved flag bit set → 400; version 3 → 426.

## 12. Open questions

1. Port 2468 — acceptable, or prefer another?
2. Stretch the passphrase (PBKDF2-SHA256, available in mbedtls as `mbedtls_pkcs5_pbkdf2_hmac_ext`) before HKDF, once at startup? Costs ~1 s on an MT7628 at boot, makes weak passphrases much harder to guess offline.
3. Should the default passphrase refuse to run at all in 2.0 (opt-in `allow_default_passphrase`), or keep "works out of the box" with warnings?
4. Compress the plaintext (flag bit) for large client lists, or not needed on LANs?
