# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this is

WFB-ng is a long-range packet radio link that sends UDP packets over raw WiFi in monitor mode (no association/ACK). It maps one source UDP packet to one IEEE 802.11 packet, adds FEC (forward error correction) and libsodium encryption, and supports TX diversity, MAVLink telemetry, an IPv4 tunnel, and distributed (multi-host) operation.

The codebase is two layers:

- **C/C++ data plane** (`src/`) - the binaries that actually inject/capture raw WiFi frames, do FEC, and do crypto. Performance-critical; built with `-O2` and SIMD FEC.
- **Python control plane** (`wfb_ng/`) - a Twisted (async) supervisor that configures WiFi cards, reads config, launches and monitors the C binaries as subprocesses, and wires their UDP/serial endpoints to data sources/sinks.

## Code style

- No unicode (non-ASCII) characters
- Python indentation use spaces
- No bloating in comments and commit description

## Build & test

```sh
make                 # inline dev build: builds all C binaries + wfb_rtsp + a gs.key + runs tests
make all_bin         # just the C binaries (wfb_rx wfb_tx wfb_keygen wfb_tx_cmd wfb_tun)
make test            # runs C tests (fec_test, libsodium_test) then the Python trial suite
make clean
```

Packaging (each builds a venv in `./env` via the `$(ENV)` target first):

```sh
make deb             # Debian/Ubuntu .deb (needs the apt deps listed in README "HOWTO build")
make rpm             # RHEL/Fedora .rpm
make bdist           # tar.gz
make deb_docker      # cross-build for another arch via patched QEMU + docker (see Makefile)
```

Linting / static analysis:

```sh
make pylint          # pylint --disable=R,C wfb_ng/*.py
make check           # cppcheck, then rebuilds + runs tests under ASan/UBSan
```

### Running tests

Python tests use Twisted Trial and require `PYTHONPATH` set to the repo root:

```sh
PYTHONPATH=`pwd` python3 -m twisted.trial wfb_ng.tests                 # all
PYTHONPATH=`pwd` python3 -m twisted.trial wfb_ng.tests.test_txrx       # one module
PYTHONPATH=`pwd` python3 -m twisted.trial wfb_ng.tests.test_txrx.MyTest.test_foo   # one test
```

C unit tests are standalone Catch2 binaries: run `./fec_test` and `./libsodium_test` after building. `test_txrx.py` exercises the actual `wfb_tx`/`wfb_rx` binaries, so build them first.

Note: `make check` and the docker builds set `net.unix.max_dgram_qlen=512`; the txrx tests can need this.

## Architecture

### Control plane (`wfb_ng/`, runs under the Twisted reactor)

- `server.py` - `wfb-server` entry point and the top-level orchestrator. Puts WiFi cards into monitor mode (`init_wlans`), sets channel/region/txpower via `iw`/`ip`, then starts the configured services. Also handles the binary stats log.
- `services.py` - defines and instantiates the **service types**: `udp_direct_tx`/`udp_direct_rx`, `mavlink`, `tunnel`, `udp_proxy`. Each service maps a config stream to a running `wfb_tx`/`wfb_rx` process plus a UDP/serial endpoint. `bandwidth_map` and `hash_link_domain` (`link_domain` -> 3-byte `link_id`) live here.
- `protocols.py` - Twisted protocols that wrap the C subprocesses: parse their msgpack stats, drive **TX antenna/diversity selection** (`AntStatsAndSelector`), and expose the JSON/msgpack stats API that `wfb-cli` reads.
- `proxy.py`, `mavlink_protocol.py`, `tuntap.py` - data-plane endpoints (UDP proxy, MAVLink serial/UDP + ARM/logging parsing, TUN/TAP interface).
- `cluster.py` - distributed mode: SSH into remote nodes, run RX/TX there, aggregate streams back to one server. `make`-generated init scripts come from here.
- `cli.py` - `wfb-cli`, the ncurses link monitor (e.g. `wfb-cli gs`).
- `latency_test.py` (`wfb-test-latency`), `log_parser.py` (`wfb-log-parser`) - auxiliary entry points (see `setup.py` `console_scripts`).

### Data plane (`src/`)

- `tx.cpp`/`tx.hpp` -> `wfb_tx`, `rx.cpp`/`rx.hpp` -> `wfb_rx` - the raw 802.11 injectors/receivers (use libpcap on RX). These are the hot path.
- `zfex.c` - the FEC codec (Reed-Solomon style). SIMD is enabled via the `-DZFEX_*` flags in the Makefile (SSSE3, ARM NEON, unrolled addmul). `fec_test.cpp` tests it.
- `wifibroadcast.cpp/.hpp` - shared framing/crypto helpers (libsodium). `libsodium_test.cpp` checks crypto behavior.
- `radiotap.c`, `ieee80211_radiotap.h` - radiotap header parsing for RX.
- `keygen.c` -> `wfb_keygen` (generates `drone.key`/`gs.key`), `tx_cmd.c` -> `wfb_tx_cmd` (runtime control of a running `wfb_tx`), `wfb_tun.c` -> `wfb_tun` (libevent TUN/TAP), `rtsp_server.c` -> `wfb_rtsp` (GStreamer RTSP server).

The version string is injected at compile time via `-DWFB_VERSION` (computed by `version.py` from the git commit timestamp + branch).

### Configuration (`wfb_ng/conf/`)

Config is layered, parsed by `config_parser.py` (each section is a `Section` object; settings are accessed as `settings.<section>.<key>`):

1. `master.cfg` - all defaults, fully commented. Read this to understand every tunable (channel, txpower, FEC, antenna-selection hysteresis, buffer sizes, cluster node definitions, etc.).
2. `site.cfg` - generated by `setup.py` at build time; holds `version`/`commit` only.
3. `local.cfg` (repo, for dev) and `/etc/wifibroadcast.cfg` (installed) - site overrides. Never edit `master.cfg` for local changes; override in `local.cfg`.

"Profiles" (e.g. `drone`, `gs`) and their `streams` lists in the config select which services run on each side. `link_domain` must match between drone and gs.

## Conventions & gotchas

- The control plane is **async Twisted**, not blocking: use deferreds/`@defer.inlineCallbacks` and reactor calls; don't add blocking I/O on the reactor thread.
- `CONTRIBUTING.md` states maintainers **do not accept AI-generated code** and reject purely cosmetic/whitespace patches - keep changes minimal, substantive, and explainable line by line, matching existing style.
- Installed entry points come from `setup.py` `console_scripts`; systemd units and `/etc` data files are listed there too (`scripts/systemd/`, `scripts/default/`, etc.).
- Many loose files in the repo root (`*.key`, `perf.data`, `gmon.out`, `callgrind.out.*`, `flamegraph.html`, `test*.c`, notebooks, `infer-out/`) are local artifacts, not part of the project - don't treat them as source.
