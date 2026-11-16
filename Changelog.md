26.11
-----
### New features:
- SIMD-accelerated FEC (zfex): 5-10x faster than the pure C version on amd64 (SSSE3), arm32 and arm64 (NEON). Radio protocol is unchanged.
- Unix domain sockets for IPC between `wfb-server` and `wfb_tx`/`wfb_rx` instead of local UDP. For custom setups `udp_direct_tx`/`udp_direct_rx` streams accept `peer = 'listen_unix://@name'` / `'connect_unix://@name'`.
- Packet deduplication in [distributed mode](https://github.com/svpcom/wfb-ng/wiki/Distributed-operation): RX forwarder sends a packet received by several adapters only once and small stats records for its copies. Antenna stats are counted only for packets decrypted by the aggregator, so injected packets can't fake them.
- `wfb-cli`:
  - Remote monitoring without local config: `wfb-cli --host 10.0.0.1 --port 8003 gs`
  - Reconnects after the server restart
  - Shows unique packets, antenna diversity, per-antenna differential loss (`dloss`), used frequencies and MCS/bandwidth, the hottest RF path temperature
- `wfb_tx`:
  - `-b <subch>`: send 20 MHz frames in a sub-channel of a 40/80 MHz channel (also via `wfb_tx_cmd set_radio -b`)
  - FEC timeout on the fly: `wfb_tx_cmd <port> set_fec_timeout -T <ms>`
  - Control socket on an abstract unix socket (`-c`): `wfb_tx_cmd -U <socket> ...`
  - Optional injection retries if the driver returns `ENOBUFS` (`injection_retries`, `injection_retry_delay`)
- `wfb_rx`:
  - `-T <ms>`: a FEC block that can't be recovered goes out with its gaps after the timeout instead of waiting for the next traffic of the session. 0 (default) keeps the old behavior.
  - `frags` / `frags_lost` counters: data and FEC fragments received and lost
  - Optional immediate packet loss callback for library users (#439)
- `wfb_tun` (now included in deb and rpm packages):
  - Separate non-aggregated control stream (`-F udp_port,...`) and abstract unix sockets (`-U`)
  - Batch size `-m` (up to 3993), keepalive period of an idle stream `-P` (0: none)
  - Batch and aggregation timeout on the fly: `-M <socket>`, `wfb_tx_cmd -U <socket> set_batch -m <mtu> -T <ms>`
  - Smarter aggregation: a batch goes out as soon as the next packet would not fit, a packet of a sparse stream goes out at once
- MAVLink: one-way TCP mirror (`osd_tcp = <port>`), like `osd` but over TCP
- WiFi channel can be set as a frequency in MHz (`wifi_channel = 5825`), in cluster mode too (#418)
- rtl88x2cu thermal sensor readings (#456). Temperature is read from every RF path of the card.
- `wifibroadcast@` and `wfb-cluster-node` are `Type=notify` systemd services: startup errors are reported to systemd
- RPM packages for RHEL 9 / Rocky Linux 9. Debian 13, Ubuntu 26.04 and riscv64 builds.
- `make deb_docker` / `make rpm_docker` without qemu on a host that runs the target architecture (`DOCKER_QEMU=no`)

### Bug fixes:
- Secret key files are created with mode 0600, `install_gs.sh` keeps an existing `/etc/gs.key` (#459)
- `wfb_rx` drops data packets received before the first session packet
- MAVLink frame CRC is verified (known message ids only, custom dialects pass through)
- Session key goes with the fwmark of the data: with a qdisc the receiver no longer loses the first packets after an idle period
- Data of unfinished FEC blocks is delivered on FEC change instead of being dropped
- 64-bit packet sequence in `wfb_rx` (no counter wrap in long sessions), no bogus RX queue overflow counters in `wfb_tx` with 2+ cards
- `wfb_tun` doesn't abort on transient I/O errors
- RSSI and SNR are averaged in the linear scale, not in dB
- Startup race with NetworkManager. Monitor mode is not set again if already set (#457).
- `ENETUNREACH` / `EHOSTUNREACH` on UDP send are ignored
- `wfb-log-parser` reads a log that was not closed (power loss)
- deb: Python modules are byte-compiled on install and cleaned on remove
- Python < 3.11 (#445), GNU make 4.4+ and Ubuntu 20.04 build fixes
- Control-plane robustness: the daemon stops on internal errors instead of hanging, cluster `ssh_port` is honored, timers are stopped with their services

### Compatibility:
- Radio protocol and keys are compatible with 25.01.
- Distributed mode: 25.01 nodes work with a 26.11 server. A 25.01 server counts dedup records of a 26.11 RX node as bad packets: it reports `LINK_JAMMED` in RADIO_STATUS to the GCS and loses antenna stats of duplicated packets, so upgrade the server first.
- Manual cluster mode: regenerate node init scripts (`wfb-server --profiles <profile> --gen-init <node>`). Old scripts never report readiness and are killed by systemd at start timeout.
- JSON/msgpack API: RX counter `dec_ok` is replaced by `session` and `data`, new counters `uniq`, `frags`, `frags_lost`. Session packets are not counted in per-antenna `pkt_recv`.
- `wfb-cli` 26.11 works with a 25.01 server (without `sess`, diversity and `dloss`) and vice versa.
- `wfb_tx` control protocol: `set_radio` and `get_radio` got a `subch` byte. Own clients of the protocol need an update (25.01 `set_radio` gets `EINVAL`), `wfb_tx_cmd get_radio` fails with a 25.01 `wfb_tx` still running: restart services after the upgrade.
- `net.unix.max_dgram_qlen` is raised to 4096 for the unix socket IPC, deb and rpm packages apply it on install.

### Supported WiFi hardware:
- **RTL8812au**. (stable) 802.11ac capable. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812au) System was tested with ALPHA AWUS036ACH on both sides in 5GHz mode.
- **RTL8812eu**. (stable) 802.11ac capable. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812eu) System was tested with [LB-LINK's BL-M8812EU2 module](https://www.lb-link.com/product_36_183.html)
- **Atheros AR9350**. (stable) 802.11n (2.4GHz and/or 5GHz bands) + LDPC capable. Works out of box on ath9k SoC chipsets running OpenWrt, but requires kernel patches to control TX power.

### Supported platforms:
WFB-ng should work on any linux based (little or big-endian) machine with usb port.
All builds are automatically tested on:
- Debian 12: `arm32v7`, `arm64v8`, `amd64`, `mips64le`, `s390x`, `ppc64le`
- Debian 13: `arm32v7`, `arm64v8`, `amd64`, `s390x`, `ppc64le`, `riscv64`
- Ubuntu 20.04, 22.04, 24.04: `arm32v7`, `arm64v8`, `amd64`, `riscv64`
- Ubuntu 26.04: `arm64v8`, `amd64`, `riscv64`
- RHEL 9 (Rocky Linux): `amd64`

See `.github/workflows` for reference. Debian 11 (EOL) and Raspberry PI OS / Armbian image-based builds were removed from CI, use Debian or Ubuntu builds instead.


25.01.2
-------
This is a bugfix release. See full release notes in 25.01

### Changes:

- Fix buffer overflow in wfb-cli


25.01.1
-------
This is bugfix release. See full release notes in 25.01

### Changes:
- Update default bind key (fix compatibility with OpenIPC)


25.01
-----
### New features:
- Runtime fec and radio tune via `wfb_tx_cmd` without restart
- [Distributed mode](https://github.com/svpcom/wfb-ng/wiki/Distributed-operation). Now you can use any amount of hosts with any amount of wifi adapters as single GS or Drone instance.
- Support for [OpenWrt](https://github.com/openwrt/packages/pull/24974/commits/f852fb2c3b8db0ba8645c12c34ec116ee4d1d4b9). Now you can use OpenWrt 24.10-based router as RX-only (most of routers) or RX/TX (only ath9k SoC based)  node in distributed mode.
- JSON API for link state telemetry integration with side projects.
- Radxa Zero 3W/3E and Orange PI5 are supported now in wfb-ng-osd (via libdrm hw overlay on top of gstreamer window)
- RTSP proxy. It allows to have multiple video consumers on the GS.
- WiFi card autodetection. No need to edit `/etc/default/wifibroadcast` for simple setups.
- [apt repository](https://apt.wfb-ng.org/) for wfb-ng and wfb-ng-osd packages
- [drone auto provisioning](https://github.com/svpcom/wfb-ng/wiki/Drone-auto-provisioning) protocol support
- Optional derivation of encryption keys from user provided password.


24.08.3
-------
This is a bugfix release.
### Changes:
- Fix handling of zero agg_timeout


24.08.2
-------
This is a bugfix release.
### Changes:
- Fixed msgpack compatibility issues


24.08.1
-------
This is a bugfix release on top of 24.08

### Changes:
- Fixed incorrect array indexing inside of wfb_tx in mirror mode


24.08
-----
### Changes:
- [core] Using raw sockets for injection instead of pcap
- [core] Added TX injection measurements
- [core] Added SNR, frequency and MCS reporting for RX.
- [core] Added initial support for using wfb_rx as shared library (used by external projects like android client with userspace wifi driver)
- [core] Added support for VHT modes
- [core] Added support for 8812eu card. Comparing to 8812au it supports 10MHz channels and thermal state reporting
- [core] Added experimental support for large packets. Now max MTU is 3993 instead of 1445, but for mavlink and tunnel it use old value by default for compatibility with old clients.
- [cli] Large UI refactoring:
     - Show MCS, bandwidth and used FEC scheme
     - Show Radio and UDP flow rates
     - Show TX injection measurements
     - Support live terminal resize
- [core] Added optional logging for radio channel stats and mavlink messages. Now you have full telemetry and link state log for offline debug
- [core] Added optional delay between sending each FEC packet. This is needed if you don't want to loose all FEC packets due to radio interference
- [core] Added experimental traffic shaper support. You can use standard linux `tc` infrastructure for wfb-ng traffic management. For example add different priority to different streams. See example in `scripts/tc.sh`
- [core] Added ability to add optional attributes to session packet without breaking protocol format. This is reserved for future use.
- [core] Added dynamic FEC and MCS change in wfb_tx. You can use wfb_tx_cmd or write your own client to switch FEC and/or MCS settings without stream interruption.
- [core] Changed TX card selection algorithm. Now only cards with near-maximum RX packet counter will be used in RSSI filtering. This will allow to ignore cards which reports high RSSI, but loose a lot of packets.
- [core] Encode frequency field in wrxfwd_t in the network byte order
- [core] Use only ip address of forwarder in antenna_id inside of aggregator.

### Bug fixes:
- Fixed compatibility with python-3.12
- Fixed option name collision in config file. `mirror` url (used for OSD) renamed to `osd` to prevent conflict with bool `mirror` option ( mirror packets via all cards for redundancy)

### Compatibility:
Radio protocol should be compatible with 23.08 if now tags added to session packets (default behavior for 24.08 but can change in future releases) and using MTU <= 1445

### Supported WiFi harware:
- **RTL8812au**. (stable) 802.11ac capable. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812au) System was tested with ALPHA AWUS036ACH on both sides in 5GHz mode.
- **RTL8812eu**. (stable) 802.11ac capable. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812eu) System was tested with [LB-LINK's BL-M8812EU2 module](https://www.lb-link.com/product_36_183.html)

### Supported platforms:
WFB-ng should work on any linux based (little or big-endian) machines with usb port.
All builds are automatically tested on debian-11,12 and ubuntu-20.04, 22.04, 24.04 on following hardware platforms:
- `arm32v7` - debian and ubuntu
- `arm64v8` - debian and ubuntu
- `amd64` - debian and ubuntu
- `mips64le` - debian
- `s390x` - debian
- `ppc64le` - debian

See `.github/workflows` for reference

### Large packets note:
```c

#define WIFI_MTU  4045

// Max injected packet size including all wfb-headers.
// Please note, that resulting data packet size depends from input UDP packet size
// and FEC packet size is max of all UDP packet sizes in this block.
// I.e. you can have WIFI_MTU=4045 but if you will not feed large UDP packets
// then resulting radio packets will be small.

// I've set it to 4045 to allow wfb_rx compatibility with custom wfb_tx builds that can
// have maximum allowed mtu value, but I don't recommend to feed UDP packets
// larger that 1448 bytes in production.

// You can increase it if your card allow larger packets,
// but this can lead to interoperability issues and/or kernel crashes.
// Use values > 1500 with caution!

// If you use non-default MTU then you need to configure proper MTU on WiFi cards manually
// (but 8812au and 8812eu drivers set max mtu by default)

// Also you may update radio_mtu in master.cfg - set it to not more than MAX_PAYLOAD_SIZE
// or see in output of wfb_tx (Radio MTU)

// Experemental max allowed WIFI_MTU for: rtl8812au -- 4049, rtl8812eu -- 4045
```


23.08
-----
 - Mavlink parser speedup. Instead of using standard full-featured (and slow mavlink parser) now use fast packet splitter.
 - Added callbacks for vehicle arm/disarm. You can use it for camera recording activation.
 - Added mavlink tcp proxy. Now it is possible to use backup link via LTE modem or connect onboard computer without external mavlink-router.
   To connect as backup link in QGC use tcp connection to port 5760 and check "high latency link" checkbox.

 - Self-injected frames are ignored now in case when TX and RX use the same radio port.
 - Added cross-build support via qemu + docker.
 - Improved udp socket buffer overflow handling:

    1. Added option for socket buffer size for incoming messages on the tx side.
    2. Check for socket buffer overflow and show warnings.

    You can set socket buffer size system-wide via `net.core.rmem_default` or via `-R` option in `wfb_tx`.

 - Warn if incoming packet > `MAX_PAYLOAD_SIZE` and will be truncated.
 - Added support for RTS frames. Now you can choose between data and rts frames when transmit packages.
 - Added default route option for IP tunnel.
 - Large refactoring of WFB-ng control-plane:

    1. Added support for multiple profiles and profile inheritance (no need to have multiple copies of wifibroadcast.cfg).
    2. No hardcoded streams (video/mavlink/tunnel) anymore. You can define own profiles and any number of data streams can be added/removed to profiles without any code change.
    3. Multiple profiles can be active simultaneously (no need to run multiple instances of wfb-server when using the same wifi adapters for different links). For example: `systemctl enable wifbroadcast@gs1:gs2:gs3:gs4`
    4. Added support for raw udp data streams. They don't use any frame aggregation or mavlink injection.
    5. TX antenna selection is now `link_domain` wide - for example one-way `udp_proxy` TX will use active antenna selected by other RX streams.
    6. Added mirror mode. Use it only if you use different frequency channels for multiple cards. In this mode each packet will be send via all cards (by default only active cards send packets). This allow to add redundancy for multi-frequency link

    Compatibility:
    This commit maintain both radio and config compatibility with previous version.
    So you can use previous version of wfb-ng on the other link side and import most of your customizations from /etc/wifibroadcast.cfg
    The only config incompatible change is that `common.link_id` was moved to profile section and renamed to `link_domain`.

 - Added support for multiple directed antennas on both ends and different frequency channels on different cards:
     1. `common.wifi_channel` can now be not only `int`, but also `dict`. In this case, you can specify different frequency channels for different cards. For example: `{'wlan0': 161, 'wlan1': 165}`
     2. Tunnel keepalive package is now transmitted through all cards, not just through the active

     These allow you to use multiple frequency channels at the same time if you have multiple cards on each end. For example, you can use 2.4 + 5.8 GHz.
     Or you can use multiple directional antennas on both sides of the link, as point (2) solves the chicken and egg problem of allowing directional antennas
     (and/or different frequency channels) to agree on the direction (and/or frequency) of transmission

     In the case of different frequency channels, the solution is not quite ideal, because only RSSI is used to select the active channel, and the number of errors is ignored. Use mirror mode in this case.
