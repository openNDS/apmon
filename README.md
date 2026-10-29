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

## Command line

`apmond` is also a thin ubus client of the running daemon. Output is JSON (as `ubus call` prints it); add `-t` or `--table` for aligned tables.

    apmond status                     this node: role and why, ULAs, collector, counters, local blocks
    apmond nodes                      collector: every reporting node
    apmond clients [node]             collector: clients (stale ones marked stale* in tables)
    apmond node <id>                  collector: one node's last report
    apmond block add <name> <json> [ttl]
    apmond block remove <name>
    apmond forget <node|client>       collector: drop a node with its clients, or one client
    apmond read_log [-f]              print the log; -f keeps following it
    apmond bench                      key derivation time on this hardware
    apmond run [-c confdir]           the daemon itself (started by /etc/init.d/apmond)

Example:

    # apmond -t nodes
    ID                 HOSTNAME  ROLE       STATE  AGE  CLIENTS  LOST  SOURCE                  PASSPHRASE
    52:54:00:12:34:01  OpenWrt   collector  ok     4s   1        0     local                   DEFAULT
    52:54:00:12:34:02  OpenWrt   peer       ok     5s   0        0     fd46:cfe5:34c5:6ddd::1  DEFAULT

## Logging

As apmond 1.x: messages above `debuglevel` (0 errors, 1 notices (default), 2 info, 3 debug) are dropped and identical consecutive messages are written once. Errors and notices go to syslog and to the log file; info and debug go to the log file only. The log file is `<log_mountpoint>/apmond/apmond_log.log` (default `/tmp/apmond/apmond_log.log`), trimmed to `max_log_entries` lines (500), each line `<date> daemon.<level> apmond[<pid>]: [<n>] <message>`. A `log_mountpoint` that is not mounted disables the log file so it can't fill flash.

## Adding data from other programs (extension blocks)

Any program on a node can attach a JSON object to that node's reports:

    ubus call apmond add_block '{"name":"mesh","data":{"peers":2},"ttl":90}'
    ubus call apmond remove_block '{"name":"mesh"}'

The collector shows it in `apmond node <id>` under `report.blocks.mesh`. Names: 1–32 of `a-z 0-9 _ -`; data up to 16 KiB; up to 16 blocks; RAM only; `ttl` (seconds) makes a block expire unless it is set again. This is how a rewritten mesh11sd can add its mesh data without its own reporting code. See docs/PROTOCOL.md section 9.
