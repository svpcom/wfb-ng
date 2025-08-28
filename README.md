![WFB-ng](doc/logo-big.png)

This is the next generation of long-range **packet** radio link based on **raw WiFi radio**

Main features:
--------------
 - **1:1 map of RTP to IEEE80211 packets for minimum latency** (doesn't serialize to byte stream)
 - **Smart FEC support** (there are many FEC improvements which allow to reduce latency in case of packet loss)
 - **Accelerated FEC** (using SIMD instructions) on amd64, arm32 and arm64 platforms. **5-10x** times faster than pure C version.
 - [Bidirectional mavlink telemetry](https://github.com/svpcom/wfb-ng/wiki/Setup-HOWTO). You can use it for mavlink up/down and video down link.
 - **IPv4 tunnel for generic usage.** You can transmit ordinary ip packets over WFB link. Note, don't use ip tunnel for high-bandwidth transfers like video or mavlink because it has more overhead than raw udp streams.
 - **Automatic TX diversity** (select TX card based on RX RSSI)
 - **Stream encryption and authentication** ([libsodium](https://download.libsodium.org/doc/))
 - **Distributed operation.** It can gather data from cards on different hosts. So you aren't limited to bandwidth of single USB bus.
 - **Aggregation of mavlink and tunnel packets.** Doesn't send wifi packet for every mavlink or tunnel packet.
 - **Dynamic FEC and radio modulation.** You can change channel capacity/reliability without link interruption.
 - **Full channel state logging including mavlink parser.** You can log all telemetry and link state for future offline debug.
 - **Support for traffic shaper**. You can use standard linux traffic shapers to priority different channels and/or data/fec packets.
 - Enhanced [OSD](https://github.com/svpcom/wfb-ng-osd) for Raspberry PI (consume 10% CPU on PI Zero) or any other system which
   supports gstreamer and OpenGL (Linux X11/Wayland, etc). Compatible with any screen resolution.
 - Supported CPU architectues: **arm32v7, arm64v8, amd64, mips64le, s390x, ppc64le, i386**. I.e. any linux with kernel >= 4.x and usb port.

> :warning: **Warranty/Disclaimer** <br />
> This is free software and comes with no warranty, as stated in parts 15 and 16 of the GPLv3 license. The creators and contributors of the software are not responsible for how it is used.
> See [License and Support](https://github.com/svpcom/wfb-ng/wiki/License-and-Support) for details.


## Support project
If you like WFB-ng you can support author via:
- https://boosty.to/svpcom/donate
- `bitcoin:bc1qfvlsvr0ea7tzzydngq5cflf4yypemlacgt6t05`

## Wiki: [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/svpcom/wfb-ng)
See https://github.com/svpcom/wfb-ng/wiki for additional info

## Community support:
Telegram group: (**wfb-ng support**) https://t.me/wfb_ng
Please note, that it is only one official group.

## Supported WiFi hardware:
 - **RTL8812au**. (stable) 802.11ac capable. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812au) System was tested with ALPHA AWUS036ACH on both sides in 5GHz mode.
 - **RTL8812eu**. (stable) 802.11ac capable. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812eu) System was tested with [LB-LINK's BL-M8812EU2 module](https://www.lb-link.com/product_36_183.html)
 - **Atheros AR9350**. (beta) 802.11n (2.4GHz and/or 5GHz bands) + LDPC capable. Should work out of box, but requires kernel patches **to control TX power** (by default it will use max power). System was tested with [TP-Link CPE510](https://openwrt.org/toh/tp-link/cpe510), but should work with all similar devices.

##### NOTE:
- For Atheros SoC you need to use [cluster mode (beta)](https://github.com/svpcom/wfb-ng/wiki/Distributed-operation) due to CPU, Flash and RAM limits.
- If you want only RX then in theory any card with monitoring mode will be suitable. For example you can try your OpenWRT-enabled router.

## Getting Started

For detailed instructions on how to get started read through
[PX4-Guide](https://docs.px4.io/main/en/companion_computer/video_streaming_wfb_ng_wifi.html)
and follow the [Setup HowTo](https://github.com/svpcom/wfb-ng/wiki/Setup-HOWTO)

### Quick start using Raspberry Pi

- Under [Releases](https://github.com/svpcom/wfb-ng/releases) download the latest image file (`*.img.gz`).
- Unpack the `*.img` file and flash it to 2-SD Cards.
- Plug the WiFi Adapters into the Raspberry Pis
- Boot the Pis and ssh into them using the following command (replace `192.168.0.111` with their IP-Address). Password: `raspberry`
```
ssh pi@192.168.0.111
```

For putty users don't forget to select: `Settings -> Window -> Translation -> Enable VT100 line drawing` checkbox before connect.

- On the Pi used as ground station:
```
sudo systemctl enable wifibroadcast@gs
sudo systemctl enable rtsp
sudo systemctl enable fpv-video
sudo systemctl enable osd
sudo reboot
```

- On the Pi used on the drone:
```
sudo systemctl enable wifibroadcast@drone
sudo systemctl enable fpv-camera
sudo reboot
```
- Done! You should be able to see the video from the FPV camera. To monitor the link use the following command on the ground station:
```
wfb-cli gs
```

### Quick start using Debian or Ubuntu Ground Station

- Install patched `RTL8812AU` or `RTL8812EU` driver:
```
sudo apt-get install dkms
# For 8812au:
git clone -b v5.2.20 https://github.com/svpcom/rtl8812au.git
cd rtl8812au/
# For 8812eu:
git clone -b v5.15.0.1 https://github.com/svpcom/rtl8812eu.git
cd rtl8812eu/
# For both:
sudo ./dkms-install.sh
```
- Get the name of the WiFi card by running:
```
ifconfig
```
- You should see output similar to:
```
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 2312
        ether 0c:91:60:0a:5a:8b  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
- Run `$ ethtool -i wlan0` and ensure that it show right driver: `rtl88xxau_wfb` or `rtl8812eu`
- Download and run [install_gs.sh](https://raw.githubusercontent.com/svpcom/wfb-ng/refs/heads/master/scripts/install_gs.sh):
```
curl -o install_gs.sh https://raw.githubusercontent.com/svpcom/wfb-ng/refs/heads/master/scripts/install_gs.sh
sudo bash ./install_gs.sh
```
- Done! To monitor the link use the following command on the ground station:
```
wfb-cli gs
```


**Failing to get connection?**

1. Check WFB-ng GS logs with `sudo journalctl -xu wifibroadcast@gs`. If there is any errors then try to resolve it.
2. If there are any encryption errors then ensure that `drone.key` and `gs.key` on drone and gs corresponds each other.
2. Make sure the WiFi channel and link domain on the ground and on the drone are the same. To check, see `/etc/wifibroadcast.cfg` and ensure that `[common] wifi_channel` and `[drone] link_domain` / `[gs] link domain`  is the same on the ground and on the drone.

---


## FAQ
**Q: What type of data can be transmitted using WFB-ng?**

**A:** Any UDP with packet size <= 3993. For example x264/265 inside of RTP, Mavlink or generic IPv4 via tunnel.

**Q: What are transmission guarantees?**

**A:** WFB-ng uses FEC (forward error correction) which can recover 4 lost packets from 12 packets block with default settings. You can tune it to fit your needs.

**Q: Is only Raspberry PI supported?**

**A:** WFB-ng is not tied to any GPU - it operates with UDP packets. But to get RTP stream you need a video encoder (which encodes raw data from camera to x264 stream). In my case RPI is only used for video encoding (because RPI Zero is too slow to do anything else) and all other tasks (including WFB-ng) are done by other board (NanoPI NEO2).

**Q: What is a difference from original wifibroadcast?**

**A:** Original version of wifibroadcast uses a byte-stream as input and splits it to packets of fixed size (1024 by default). If radio packets were lost and this is not corrected by FEC you'll get a hole at random (unexpected) place of stream. This is especially bad if data protocol is not resistant to (was not desired for) such random erasures. So i've rewritten it to use UDP as data source and pack one source UDP packet into one radio packet. Radio packets now have variable size depending on payload size. This reduces video latency a lot.

## Theory
WFB-ng puts the wifi cards into monitor mode. This mode allows to send and receive arbitrary packets without association and waiting for ACK packets.
- [WFB-ng design and protocol description](https://github.com/svpcom/wfb-ng/blob/master/doc/wfb-ng-std-draft.md)
- [Analysis of Injection Capabilities and Media Access of IEEE 802.11 Hardware in Monitor Mode](https://github.com/svpcom/wfb-ng/blob/master/doc/Analysis%20of%20Injection%20Capabilities%20and%20Media%20Access%20of%20IEEE%20802.11%20Hardware%20in%20Monitor%20Mode.pdf)
- [802.11 timings](https://github.com/ewa/802.11-data)

## Sample usage chain:
```
Camera --[RTP stream (UDP)]--> wfb_ng --//--[ RADIO ]--//--> wfb_ng --[RTP stream (UDP)]--> gstreamer --> Display
```

- For encoding video from OpenIPC-based security camera connected via ethernet to your PC or SBC you don't need a special pipeline. Just set `outgoing` to `udp://your_ip_address:5602` in [majestic.yaml](https://github.com/OpenIPC/wiki/blob/master/en/majestic-streamer.md#other-outgoing-options)

- For encoding video from a Raspberry Pi Camera (obsolete, latency is high comparing to OpenIPC):
 ```
 raspivid -n  -ex fixedfps -w 960 -h 540 -b 4000000 -fps 30 -vf -hf -t 0 -o - | \
                gst-launch-1.0 -v fdsrc ! h264parse ! rtph264pay config-interval=1 pt=35 ! udpsink sync=false host=127.0.0.1 port=5602
 ```

- For encoding video from Logitech C920 camera (obsolete, camera is EOL many years ago):
 ```
 gst-launch-1.0 uvch264src device=/dev/video0 initial-bitrate=6000000 average-bitrate=6000000 iframe-period=1000 name=src auto-start=true \
                src.vidsrc ! queue ! video/x-h264,width=1920,height=1080,framerate=30/1 ! h264parse ! rtph264pay ! udpsink host=localhost port=5602
 ```

- To decode:
 ```
 gst-launch-1.0 udpsrc port=5600 caps='application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264' \
                ! rtph264depay ! avdec_h264 ! clockoverlay valignment=bottom ! autovideosink fps-update-interval=1000 sync=false
 ```

## HOWTO build:

For development (inline build)
```
make
```

For binary distribution RHEL or Fedora
```
make rpm
```

For binary distribution Debian or Ubuntu
```
sudo apt install python3-all libpcap-dev libsodium-dev libevent-dev python3-pip python3-pyroute2 \
            python3-twisted python3-serial python3-all-dev iw socat virtualenv \
            debhelper dh-python fakeroot build-essential python3-msgpack \
            python3-setuptools libgstrtspserver-1.0-dev -y
sudo make deb
```

For binary distribution (tar.gz)
```
make bdist
```

You need to generate encryption keys for gs(ground station) and drone:
```
wfb_keygen
```
Leave them in place for development build or copy to `/etc` for binary install.
Put `drone.key` to drone and `gs.key` to gs.
