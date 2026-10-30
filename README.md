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

    apmond status                        this node: version and build identity, role and why, ULAs, collector, counters, debuglevel, blocks
    apmond nodes                         collector: every node with its info, APs and clients (as 1.x show_ap_data)
    apmond node <node_mac>               collector: one node, same layout as nodes
    apmond clients [node_mac]            collector: flat client list, by node then MAC (stale ones marked stale*)
    apmond forget <node_mac|client_mac>  collector: drop a node with its clients, or one client
    apmond block add <name> <json> [ttl]
    apmond block remove <name>
    apmond debuglevel [0|1|2|3]          show, or set at once and save to uci
    apmond read_log [-f]                 print the log; -f keeps following it
    apmond bench                         key derivation time on this hardware
    apmond run [-c confdir]              the daemon itself (started by /etc/init.d/apmond)

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

## Field names

Nodes are identified by `node_mac` and clients by `client_mac`, the first field of every client object. Clients nested under a node in `apmond nodes` / `node` are just `client_mac`, `kind`, `state`, `last_seen`, `last_seen_date`, `last_seen_age_s`, location (Wi-Fi `ap_ssid`, `ap_ifname`, `ap_bssid`; wired `bridge`/`port`), `vlan`, `vxlan`, then their stats (`-t` shows a Wi-Fi client's SSID under WHERE); the flat `apmond clients` list adds `node_mac` and `node_hostname` after `client_mac`.

## Times

In collector output (`apmond nodes|node|clients` and the ubus methods) client `last_seen` and node `last_report` are Unix seconds, each with a `_date` twin in apmond 1.x's `date_time` format (router local time, spaces as `_`, eg `Thu_Oct_29_15:47:00_GMT_2026`), plus `last_seen_age_s` / `age_s`. Reports on the wire keep milliseconds.

## VLANs and VXLAN

Every AP and client carries `vlan`: the access VLAN of its bridge port (PVID on a `vlan_filtering` bridge, so an AP on `option network lan` with lan on `br-lan.10` shows 10; a Wi-Fi client has its AP's VLAN, a wired client its port's). `null` means untagged / no VLAN; tables show `-`. On mesh11sd nodes, where the trunk is a VXLAN (`vxlan<tun_id>` in `br-tun<tun_id>`), APs and clients on that bridge also carry `"vxlan": {"vni": N, "device": "vxlan0"}`, otherwise `null`. Both come from rtnetlink, no forks, cached 5 minutes.

## Logging

`apmond debuglevel` prints the level; `apmond debuglevel N` (or `ubus call apmond debuglevel '{"level":N}'`) applies it at once and commits `option debuglevel` to /etc/config/apmond, as 1.x did, so it persists. A change made with `uci set apmond.setup.debuglevel=N; uci commit apmond` is picked up on the next report cycle. Every change is logged at notice level.

As apmond 1.x: messages above `debuglevel` (0 errors, 1 notices (default), 2 info, 3 debug) are dropped and identical consecutive messages are written once. Errors and notices go to syslog and to the log file; info and debug go to the log file only. The log file is `<log_mountpoint>/apmond/apmond_log.log` (default `/tmp/apmond/apmond_log.log`), trimmed to `max_log_entries` lines (500), each line `<date> daemon.<level> apmond[<pid>]: [<n>] <message>`. A `log_mountpoint` that is not mounted disables the log file so it can't fill flash.

## Adding data from other programs (extension blocks)

Any program on a node can attach a JSON object to that node's reports:

    ubus call apmond add_block '{"name":"mesh","data":{"peers":2},"ttl":90}'
    ubus call apmond remove_block '{"name":"mesh"}'

The collector shows it in `apmond node <node_mac>` under `blocks.mesh` (and in `apmond nodes`). Names: 1–32 of `a-z 0-9 _ -`; data up to 16 KiB; up to 16 blocks; RAM only; `ttl` (seconds) makes a block expire unless it is set again. This is how a rewritten mesh11sd can add its mesh data without its own reporting code. See docs/PROTOCOL.md section 9.

## Which code is running

Every node reports, right after `apmond_version`, `package_version` (eg 2.0.0_beta-r13),
`build_commit`, `running_sha256` (the binary that is running, hashed at startup),
`installed_sha256` (`/usr/sbin/apmond` on disk, re-hashed when it changes) and
`restart_needed` (true when they differ). `apmond status`, `apmond nodes` and `apmond node <mac>`
show them; `apmond -t nodes` has a line per node such as

    build 2.0.0_beta-r13 3aa8f8d  running 8a681eac  installed 8a681eac

ending in `RESTART NEEDED` when the installed binary is not the one running. The package
restarts apmond itself on an `apk` upgrade, so this normally shows only after a manual copy.
Nodes running a 2.0 beta before r13 show these fields as null.

## Security: user apmond, CAP_NET_ADMIN only

apmond does not run as root. The package creates user and group `apmond` (468), and
the init script starts it one of two ways:

- **ujail** (when `procd-ujail` is installed and the kernel has PID, IPC and UTS
  namespaces): procd jails it as user apmond with only `CAP_NET_ADMIN`
  (`/etc/capabilities/apmond.json`), no_new_privs, and these mounts: ubus, log, /proc,
  /sys, read-only `/etc/config`, `/etc/openwrt_release`, `/tmp/sysinfo`, `/usr/sbin` (so
  `installed_sha256` sees a replaced binary), `/overlay` (free flash), `/bin/sh` and
  `/sbin/swconfig` (wired speed fallback), and read-write `/tmp/apmond` plus
  `log_mountpoint` when it is not /tmp.
- **otherwise** (no ujail, or a small target such as ramips/mt76x8 whose kernel has only
  mount namespaces, where ujail cannot start): `apmond run -u apmond` starts as root and
  switches to user apmond itself, keeping only `CAP_NET_ADMIN` (bounding, permitted,
  effective, ambient) with no_new_privs, as dnsmasq does.

`CAP_NET_ADMIN` is needed to add and remove the ULA addresses over netlink; the collector
port (2468) needs no capability, and `CAP_NET_RAW` is not used. ubus access for user
apmond is in `/usr/share/acl.d/apmond.json`: publish `apmond` and call `network.interface.*`
status. Wi-Fi state comes straight from the kernel over nl80211 generic netlink (no iwinfo,
rpcd-mod-iwinfo or libnl; dumps need no capability). The postinst reloads ubusd so the
ACL applies at once.

`/etc/config/apmond` is root:apmond 0640 (set at every start): the daemon reads it,
including `debuglevel` each cycle, but cannot write it. `apmond debuglevel N` (as root)
saves the level to uci itself and restores the group; `ubus call apmond debuglevel
'{"level":N}'` changes it for the running daemon (`"persisted": false` when jailed). A
`uci commit apmond` by another tool keeps the mode but resets the group to root, so the
daemon keeps its current settings until the next restart or `service apmond reload`.
The CLI (`apmond status`, `nodes`, ...) runs as root outside the jail and talks over ubus.

`build_commit` comes from `.build_commit`, which holds `$Format:%h$`: `git archive` and
GitHub release tarballs fill in the short commit (`.gitattributes` export-subst). A build
from a plain checkout asks git, else shows "unknown".
