# OpenWrt packages for WFB-ng

## Setup HOWTO

1. Create a [custom feed](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem#creating_a_local_feed) using full path to this directory
2. Configure OpenWrt via `make menuconfig` - select `wfb-ng` or `wfb-ng-full` package according to your needs
3. Build OpenWrt via `make`
