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

`apmond` is also a thin ubus client of the running daemon. Output is JSON, indented as jq and apmond 1.x print it (two spaces; `ubus call apmond ...` keeps libubox's own format); add `-t` or `--table` for aligned tables.

    apmond status                     this node: role and why, ULAs, collector, counters, local blocks
    apmond nodes                      collector: every node with its info, APs and clients (as 1.x show_ap_data)
    apmond clients [node]             collector: flat client list, by node then MAC (stale ones marked stale*)
    apmond node <id>                  collector: one node, same layout as nodes
    apmond block add <name> <json> [ttl]
    apmond block remove <name>
    apmond forget <node|client>       collector: drop a node with its clients, or one client
    apmond read_log [-f]              print the log; -f keeps following it
    apmond bench                      key derivation time on this hardware
    apmond run [-c confdir]           the daemon itself (started by /etc/init.d/apmond)

Example:

    # apmond -t nodes
    === OpenWrt-6873  94:83:c4:52:68:73  collector  ok  last report 29s ago
        model GL-MT300N-V2  release 25.12.5  apmond 2.0.0beta
        uptime 5d 19h 12m  load 1.10 0.83 0.63  free RAM 75532 KiB  free flash 9016 KiB
        ULA fd46:cfe5:34c5:6ddd:9683:c4ff:fe52:6873  IPv4 192.168.10.1/24
        source local  reports 2  lost 0  passphrase DEFAULT
      Access points
        PHY   CHANNEL  MHZ   HTMODE  AP        SSID        BSSID
        phy0  1        2412  HT20    phy0-ap0  House-6873  96:83:C4:52:68:73
      Clients (1)
        MAC                KIND   STATE   LAST_SEEN  WHERE   SIGNAL  TX          RX          CONNECTED
        1c:86:0b:36:3f:dd  wired  active  29s        eth0.1  -       100 Mbit/s  100 Mbit/s  -

    === OpenWrt-f9d1  94:83:c4:2e:f9:d1  peer  ok  last report 3s ago
        ...

## Times

In collector output (`apmond nodes|node|clients` and the ubus methods) client `last_seen` and node `last_report` are Unix seconds, each with a `_date` twin in apmond 1.x's `date_time` format (router local time, spaces as `_`, eg `Thu_Oct_29_15:47:00_GMT_2026`), plus `last_seen_age_s` / `age_s`. Reports on the wire keep milliseconds.

## VLANs and VXLAN

Every AP and client carries `vlan`: the access VLAN of its bridge port (PVID on a `vlan_filtering` bridge, so an AP on `option network lan` with lan on `br-lan.10` shows 10; a Wi-Fi client has its AP's VLAN, a wired client its port's). `null` means untagged / no VLAN; tables show `-`. On mesh11sd nodes, where the trunk is a VXLAN (`vxlan<tun_id>` in `br-tun<tun_id>`), APs and clients on that bridge also carry `"vxlan": {"vni": N, "device": "vxlan0"}`, otherwise `null`. Both come from rtnetlink, no forks, cached 5 minutes.

## Logging

As apmond 1.x: messages above `debuglevel` (0 errors, 1 notices (default), 2 info, 3 debug) are dropped and identical consecutive messages are written once. Errors and notices go to syslog and to the log file; info and debug go to the log file only. The log file is `<log_mountpoint>/apmond/apmond_log.log` (default `/tmp/apmond/apmond_log.log`), trimmed to `max_log_entries` lines (500), each line `<date> daemon.<level> apmond[<pid>]: [<n>] <message>`. A `log_mountpoint` that is not mounted disables the log file so it can't fill flash.

## Adding data from other programs (extension blocks)

Any program on a node can attach a JSON object to that node's reports:

    ubus call apmond add_block '{"name":"mesh","data":{"peers":2},"ttl":90}'
    ubus call apmond remove_block '{"name":"mesh"}'

The collector shows it in `apmond node <id>` under `blocks.mesh` (and in `apmond nodes`). Names: 1–32 of `a-z 0-9 _ -`; data up to 16 KiB; up to 16 blocks; RAM only; `ttl` (seconds) makes a block expire unless it is set again. This is how a rewritten mesh11sd can add its mesh data without its own reporting code. See docs/PROTOCOL.md section 9.
