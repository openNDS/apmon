# apmon wire protocol, version 2

Status: **draft for review** (2.0.0beta). This is the protocol spoken by apmond 2.x and libapmon.
It is a clean design: it does not interoperate with apmond 1.x or with the script apmond built into mesh11sd.
The apmond 2.x package does **not** conflict with mesh11sd: both can be installed on the same node. On a mesh11sd node, turn off mesh11sd's built-in apmond (`uci set mesh11sd.setup.apmond_enable='0'`) so only one monitoring system runs.

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
| Port | Configurable with uci option **`apmond.setup.port`**, **default TCP 2468**. Every node MUST use the same value (senders connect to it, the collector listens on it). 2468 is clear of 80/443 (uhttpd), 2050 (openNDS) and other common OpenWrt services |
| Report path | `POST /apmon/v2/report` |
| Time sync path | `POST /apmon/v2/time` |
| Request `Content-Type` | `application/vnd.apmon.v2` (anything else: 415) |
| Response `Content-Type` | `application/vnd.apmon.v2` when the body is an encrypted message; no body otherwise |
| Max request body | 262144 bytes default (uci `max_message_size`); larger, or a missing/oversized `Content-Length`: 413. The collector MUST stop reading at the limit |
| Timeouts | sender: 10 s connect+response; collector: 15 s per connection, max 32 concurrent connections |
| Other methods / paths | 405 / 404, no body |

The listener is one dual-stack socket bound to the LAN network device (`SO_BINDTODEVICE`): the `l3_device` of `option interface` (default `lan`, eg `br-lan.10` on a VLAN setup), or `option netdev` if set, falling back to `option device`, so it answers on the LAN addresses (IPv4, the node ULA and `::1`) and never on the WAN.

**Addresses (as apmond 1.x).** The ULA /64 is derived from `sha256(apmon_seed)`: with `id` = hex characters 9–38 of the hash, the prefix is `fd<id[9..10]>:<id[11..14]>:<id[15..18]>:<id[19..22]>::/64`. Every node adds `<prefix>:<EUI-64 of its device MAC>/64` to that LAN network device. The collector candidate (role `collector`, or `auto` with a default route that does not go through the LAN network device) claims `<prefix>::1/64`, first come wins: it waits a random 0–`claim_delay_max` s, backs off if `::1` already answers on the apmond port or if DAD fails, and takes over when `::1` has been silent for `router_takeover_misses` checks. Addresses are added and removed with rtnetlink and removed when apmond stops.

Senders send to `option collector` if set, otherwise to `[<prefix>::1]:port`; if that fails they fall back to the default gateway's IPv4 address and retry the ULA every 10 reports.

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
| 6 | 2 | `flags` | bit 0 `CLOCK_FROM_COLLECTOR`: sender's timestamp is collector-referenced (section 5); bit 1 `DEFAULT_PASSPHRASE`: sender uses the built-in passphrase; bits 2–15 reserved, MUST be 0 (else 400). Bit 2 is earmarked for a future `COMPRESSED` payload; 2.0 does **not** compress |
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

The shared passphrase is uci `apmond.setup.apmon_seed` (same option name as 1.x, identical on every node).
If it is unset, a built-in default passphrase is used so apmond works out of the box (as 1.x and mesh11sd). In that case the `DEFAULT_PASSPHRASE` header flag is set on every message, the report carries `"default_passphrase": true`, both sender and collector log the periodic notice, and `ubus call apmond status` / LuCI show a warning. The default passphrase gives no real protection.

Two standard steps, both on mbedtls primitives available in OpenWrt 25.12:

1. **PBKDF2-HMAC-SHA256** (RFC 8018) stretches the passphrase, so a weak one is expensive to guess offline. mbedtls: `mbedtls_pkcs5_pbkdf2_hmac_ext()` (`MBEDTLS_PKCS5_C`: enabled in upstream mbedtls 3.6 default config and not one of OpenWrt's configurable switches, so always on in OpenWrt's libmbedtls 3.6.7; confirmed in the 25.12.6 SDK build's mbedtls_config.h).
2. **HKDF-SHA256** (RFC 5869) derives the separate working keys. Implemented in libapmon on mbedtls HMAC-SHA256, so it does not depend on `MBEDTLS_HKDF_C`, which is an optional OpenWrt build switch (default off in the package's Config.in).

```
IKM   = PBKDF2-HMAC-SHA256(password = apmon_seed as raw UTF-8 bytes (no trailing newline),
                           salt = "apmon/2 pbkdf2", iterations = 50000, dkLen = 32)
PRK   = HKDF-Extract(salt = "apmon/2 salt", IKM)
K_s2c = HKDF-Expand(PRK, info = "apmon/2 s2c" || u32be(key_epoch), L = 32)   # sender -> collector
K_c2s = HKDF-Expand(PRK, info = "apmon/2 c2s" || u32be(key_epoch), L = 32)   # collector -> sender
```

All strings are ASCII without a terminator.

| Constant | Value | Notes |
|---|---|---|
| PBKDF2 salt | `apmon/2 pbkdf2` | fixed protocol constant. Every node must derive the same key without any exchange, so the salt cannot be random; a per-network salt would need a second shared value. The cost of a fixed salt is that one precomputed dictionary works against every apmon network, which the iteration count only slows down |
| PBKDF2 iterations | **50000** | fixed protocol constant, not configurable (all nodes must agree). Estimated ≈1 s on an MT7628 (MIPS 24KEc, 580 MHz): mbedtls SHA-256 there is roughly 6 MB/s, and one iteration is two 64-byte compressions. Still to be measured on the MT300N-v2 with `apmond bench` (an x86-64 QEMU VM under software emulation took 260 ms) |
| HKDF salt | `apmon/2 salt` | |

The PBKDF2 step runs **once** at daemon start (and on reload), and the keys are kept in RAM, so the cost is not paid per message.

Separate keys per direction mean a collector reply can never be replayed to the collector as a report, even before the `type` check.

`key_epoch` (uci, default 0) allows a passphrase change without a flag day: with uci `prev_epoch_grace` (seconds, default 0 = off) the collector also accepts `key_epoch − 1` for that long after it starts, and answers in the epoch the sender used. Both key sets come from one PBKDF2 run. The ULA prefix and subnet continue to be derived from `sha256(apmon_seed)` exactly as in 1.x, so addressing is unchanged; that derivation is independent of these keys.

## 5. Time, replay window and nodes without a clock

Collector rules for every REPORT (after the GCM tag verifies — never before):

1. **Window:** `|timestamp − collector_now| ≤ max_skew` (uci `max_age`, default **120 s**). Otherwise 409.
2. **Nonce cache:** keep each accepted `(sender_id, nonce)` for `2 × max_skew`; a repeat is 409. Memory: one entry per accepted message, bounded by nodes × (240 s / interval).

(1) and (2) together are sufficient against replay. `seq` is used only to count lost reports (shown in `ubus call apmond nodes`), never to reject a message, so a sender that restarts never gets locked out.

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
    "uptime_s": 3600,
    "load": ["0.12", "0.20", "0.18"],
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
    { "client_mac": "aa:bb:cc:dd:ee:ff", "kind": "wifi", "ap_ssid": "Home", "ap_ifname": "phy0-ap0", "ap_bssid": "94:83:c4:a1:b2:c4", "vlan": null,
      "signal_avg_dbm": -58, "ack_signal_avg_dbm": -60,
      "tx_bitrate_kbps": 72200, "rx_bitrate_kbps": 65000,
      "tx_bytes": 123456, "rx_bytes": 654321, "tx_retries": 3,
      "connected_s": 1200, "inactive_ms": 1500, "last_seen": 1793270398500 },
    { "client_mac": "11:22:33:44:55:66", "kind": "wired", "bridge": "br-lan", "port": "lan1", "vlan": 10,
      "speed_mbps": 100, "last_seen": 1793270400000 }
  ],
  "blocks": {}
}
```

| Object | Required fields | Notes |
|---|---|---|
| top | `v`, `type`, `report_time`, `node`, `clients` | `radios` omitted on wired-only nodes |
| `node` | `id`, `apmond_version`, `uptime_s` | rest optional. Units are in the key: `_s` seconds, `_ms` milliseconds, `_kb` KiB, `_kbps` kbit/s, `_mbps` Mbit/s, `_dbm` dBm, `_mhz` MHz; `load` is three 2-decimal strings as 1.x; `last_seen`, `report_time` are Unix ms. Wi-Fi `connected_s` is iwinfo `connected_time` (seconds), `inactive_ms` is iwinfo `inactive` (ms). `ack_signal_avg_dbm` is null when the driver does not report it (mt76 on MT7628). Wired `speed_mbps` comes from `/sys/class/net/<port>/speed`, else for a swconfig VLAN interface (eg `eth0.1`) from `swconfig dev <sw> port <n> get link` of the VLAN's untagged ports, highest up port, as 1.x (cached 5 min per interface); null only if neither works. `vlan` (APs, Wi-Fi and wired clients) is the access VLAN of the bridge port: on a `vlan_filtering` bridge the port's PVID (else its only untagged VLAN) from an rtnetlink AF_BRIDGE dump (as `bridge vlan show`), so an AP with `option network lan` where lan is `br-lan.10` gets 10; on a bridge without VLAN filtering, the bridge's own `.N` or its one 802.1q port. A Wi-Fi client has its AP's VLAN, a wired client its port's. Cached 5 min (unknown ports re-checked after 30 s); null means untagged / no VLAN (no VLANs configured, a bridge without VLANs, or a trunk port); `-t` tables show `-`. `vxlan` (APs, Wi-Fi and wired clients, optional): `{"vni": N, "device": "vxlan0"}` when the port is a VXLAN device or its bridge has a VXLAN port, as mesh11sd builds its trunk (`vxlan<tun_id>` in bridge `br-tun<tun_id>`); from rtnetlink (`IFLA_INFO_KIND` vxlan, `IFLA_VXLAN_ID`), cached with the VLAN data; null when it does not apply |
| client | `client_mac` (collectors also accept `mac` from 2.0 betas before r8), `kind`, Wi-Fi: `ap_ssid`, `ap_ifname`, `ap_bssid` (`ap` before r9) (`wifi`/`wired`), `last_seen` | `last_seen` = `report_time − inactive_ms` for Wi-Fi; for wired, the time the FDB entry was last refreshed (`report_time − fdb age`) |
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
| `nodes` | — | as 1.x `show_ap_data all`: every node with its full node info and its clients nested under it, the collector first, then by hostname. Each node: `node_mac` (its id), every field of its report's `node` object (hostname, model, openwrt_release, apmond_version, role, uptime_s, load, free_ram_kb, free_flash_kb, cpu_*, ipv4_addresses, node_ula), the collector's view (`state` `ok`/`late`/`lost`, `age_s`, `last_report` (Unix seconds) and `last_report_date`, `source`, `reports`, `lost_reports`, `default_passphrase`, `client_count`), `radios` (with their `aps`), `blocks`, and `clients` (sorted by MAC, each as in `clients`) |
| `node` | `node_mac` (or `id`) | the same object as one entry of `nodes` |
| `clients` | `node_mac`? (or `node`), `include_stale`? | flat list for scripts, in node order then by MAC. Every client object, here and nested in `nodes`, starts `client_mac`, then (flat list only) `node_mac`, `node_hostname`, then `kind`, `state` (`active`/`stale`), `last_seen`, `last_seen_date`, `last_seen_age_s`, `ap_ssid`, `ap_ifname`, `ap_bssid` (Wi-Fi) or `bridge`/`port` (wired), `vlan`, `vxlan`, then the kind-specific stats. For senders before r9, which report only `ap` (the interface), the collector fills `ap_ssid`/`ap_bssid` from that node's `aps`. Clients nested under a node have no `node_mac`/`node_hostname`. `last_seen` is in Unix seconds (the report carries ms) plus `last_seen_date`. The `_date` fields use apmond 1.x's `date_time` format: `date` output in the router's local time with spaces as `_`, eg `Thu_Oct_29_15:47:00_GMT_2026` |
| `client` | `client_mac` | one client, with node history (last N roams) |
| `add_block` | `name`, `data` (object), `ttl` (s, optional) | any node: attach or replace an extension block in this node's reports |
| `remove_block` | `name` | any node: remove it |
| `forget` | `node_mac` (or `node`) or `client_mac` (or `client`) | collector: drop a node with its clients, or one client (a node that still reports comes back) |

`status` on every node also returns `role_reason`, `node_ula`, `collector_ula`, `collector_via` (sender: `ula`, `ipv4` or `config`) and the local `blocks` (name, size, seconds to expiry).

**Extension blocks.** A block is a named JSON object another program puts into this node's reports, so the collector receives it with no change to apmond. Names are 1–32 characters of `a-z 0-9 _ -`; the JSON text of `data` is at most 16 KiB; at most 16 blocks per node. Blocks live in RAM only, are sent in every report under `"blocks": {"<name>": {...}}` until removed, until `ttl` seconds after they were last set, or until apmond restarts. Setting a block again replaces it (and restarts its ttl), so a program refreshing every interval with a ttl of 2–3 intervals makes its data vanish automatically if it stops. The collector shows them in `ubus call apmond node '{"id":"..."}'` under `report.blocks`. Example (a future mesh11sd):

```
ubus call apmond add_block '{"name":"mesh","data":{"peers":2,"portal":"94:83:c4:00:00:01"},"ttl":90}'
```

**ubus events** (collector), watch with `ubus listen apmond.node.new apmond.node.lost apmond.client.roam`:

| Event | Data | When |
|---|---|---|
| `apmond.node.new` | `id`, `source` | first report from a node (also after `forget`) |
| `apmond.node.lost` | `id`, `source` | no report for 5 intervals (once, until it reports again) |
| `apmond.client.roam` | `client_mac`, `from`, `to` | a client appears in another node's report |

ubus ACLs restrict write methods to root.

## 10. Security considerations

- **Protected:** report contents (confidentiality), integrity and origin from a key holder, freshness (window + nonce + seq). Any node holding the passphrase can impersonate any other node id — membership is the passphrase, as in 1.x.
- **Not protected (metadata):** who talks to whom, message size and timing, and the cleartext header: sender MAC, timestamp, sequence, key epoch and the default-passphrase flag. The MAC is already visible on the LAN anyway.
- **No forward secrecy:** anyone who later learns the passphrase can decrypt captured traffic. Accepted for AP monitoring data; rotate with `key_epoch` if a passphrase leaks.
- **Low-entropy passphrases:** a captured message allows an offline dictionary attack on the passphrase. PBKDF2 (50000 iterations) makes each guess cost about as much as 50000 HMACs, but a weak passphrase is still weak. The built-in default passphrase gives **no** security; it exists only so apmond works out of the box, and both ends flag and log it. LuCI should show it prominently.
- **Nonces:** random 96-bit per message. At 1 message / 10 s per node, collision probability is negligible for decades; never use a counter-derived or fixed IV in production. Test vectors use fixed nonces **only** for testing.
- **Parsing:** only the fixed header is parsed before authentication; JSON is parsed only after the tag verifies, with size and depth limits (depth ≤ 8, ≤ 512 clients per report).
- **Exposure:** the listener binds to the ULA/LAN only; the firewall should not open the apmond port (default 2468) on WAN. Compared with 1.x, uhttpd, px5g and certificates go away. Note that 1.x TLS did not stop an active attacker either (`--no-check-certificate`).
- **No downgrade:** there is no unencrypted or weaker mode.
- **No compression** in 2.0 (avoids compression side channels and code); flag bit 2 is reserved for it.

## 11. Test vectors

Generated by `tests/vectors/gen_vectors.py` (python3-cryptography 43, Python `hashlib.pbkdf2_hmac`), which also writes `tests/vectors/vectors.h` for the C unit tests and self-checks HKDF against RFC 5869 test case A.1. All hex.

### Keys, key_epoch = 0

| Passphrase | IKM (PBKDF2) | PRK | K_s2c | K_c2s |
|---|---|---|---|---|
| built-in default | `9fcee92b4108a1c6d735be4bd3de6d0dd9e12c9b6c4ea3de868a2fe22ddc6ea9` | `a90f1b3bcdd6da7dc941a298c2f2a16e21371f09b2592d03929c34974464d0f6` | `904458537dddfd255917133e3401e6af110e21a0b94a21a2c0bc78421beffde3` | `0f3aff2fbc92efc5c75c5f865ab039572729d6717ccc18569b0f90d6f261ee45` |
| `correct horse battery staple` | `477c1958224f8916af4307f7a4fc879a30517c21c077bf112aa964673ff97516` | `d532e986fa0d33454b5934e0c00516470b8fcc0b775200afd1c47bc2166779c1` | `04535a5c12a1edaa5128cfbf6b2aa1217fafea6eca720567af8d045f53918970` | `200caea0ac4af1c794a6f9e89c2a668d09190064ed400dbd35cf1cefeed2d420` |

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
d3444498145f9d0550e98fe6c6bc44b24de70856674bd68e2d8236352a2378c1cc30907277999575350006838557ea20
2062b62754d47becc6dbed56f5d157d6284a596f5c4affbe2336dfebd30122ab6014642e0de640ee888a0dc570a3a7d6
cfba4539a8f7354ef390d17ec099a8bcb427d672f013cd7c212ad212f81c17213b
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
76ad62238463f6f12f0ffde3b8637c5e6fec31936202ba1c6249cf2eeac57effc4117992b35f87f3597b9cdcdab6e09c
6890d0970314c7483a6b9401fe1b58a94af73ac36574373284f119e0a528bbd5ea9dbabdc992269754fa91062cdd0852
a14784e82e8aea974bb70e7d7052494464508c89e7570c381c21e6807b64154843aab0d78b0ad9
```

Negative tests implementations MUST pass: flip any header byte → 401 (tag fails); flip any ciphertext byte → 401; same message twice → 2nd is 409 (nonce cache); timestamp ±121 s → 409; `ct_len` ≠ body − 48 → 400; reserved flag bit set → 400; version 3 → 426.

## 12. Open questions

1. Measure the PBKDF2 cost on the MT300N-v2 (`apmond bench`) and adjust the constant **before** 2.0.0 is released; after release it can only change with a protocol version bump.
