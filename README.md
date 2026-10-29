# apmon

ApmonD 2.0: a shared access point monitoring library (libapmon) and the apmond daemon, written in C.

The 1.x shell version lives in [openNDS/apmond](https://github.com/openNDS/apmond).

Status: **2.0.0beta, first testable build.** Protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Layout

| Path | What |
|---|---|
| `src/lib` | libapmon: PBKDF2/HKDF key derivation, AES-256-GCM envelope, replay cache, JSON writer (crypto backend: mbedtls) |
| `src/apmond` | the daemon: uloop, uci, ubus, data collection, sender, collector (libmicrohttpd) |
| `tests` | host unit tests (`make -C tests check`, add `MBEDTLS_DIR=<mbedtls 3.6 tree>` if the system has no mbedtls) and test vectors |
| `openwrt/apmond` | OpenWrt package (Makefile, `files/apmond.config`, `files/apmond.init`) |

## Using it

On every node: same `apmon_seed` and `port` (default 2468) in `/etc/config/apmond`. The node whose default route does not go through `br-lan` becomes the collector; the others send to their default gateway (or to `option collector`).

On the collector:

    ubus call apmond status
    ubus call apmond nodes
    ubus call apmond clients
    ubus call apmond node '{"id":"<node mac>"}'

`apmond bench` prints how long key derivation takes on the device.

apmond 2.x does not conflict with mesh11sd. On mesh11sd nodes set `uci set mesh11sd.setup.apmond_enable='0'` so mesh11sd's built-in (1.x protocol) apmond is off.
