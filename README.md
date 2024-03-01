![WFB-NG](doc/logo-big.png)

This is the next generation of long-range **packet** radio link based on **raw WiFi radio**

Main features:
--------------
 - 1:1 map of RTP to IEEE80211 packets for minimum latency (doesn't serialize to byte stream)
 - Smart FEC support (immediately yield packet to video decoder if FEC pipeline without gaps)
 - [Bidirectional mavlink telemetry](https://github.com/svpcom/wfb-ng/wiki/Setup-HOWTO). You can use it for mavlink up/down and video down link.
 - IP-over-WFB tunnel support. You can transmit ordinary ip packets over WFB link. Note, don't use ip tunnel for high-bandwidth transfers like video or mavlink. It uses less efficient FEC coding and doesn't aggregate small packets.
 - Automatic TX diversity (select TX card based on RX RSSI)
 - Stream encryption and authentication ([libsodium](https://download.libsodium.org/doc/))
 - Distributed operation. It can gather data from cards on different hosts. So you don't limited to bandwidth of single USB bus.
 - Aggregation of mavlink packets. Doesn't send wifi packet for every mavlink packet.
 - Enhanced [OSD](https://github.com/svpcom/wfb-ng-osd) for Raspberry PI (consume 10% CPU on PI Zero) or any other system which
   supports gstreamer (Linux X11, etc). Compatible with any screen resolution. Supports aspect correction for PAL to HD scaling.
 - Provides IPv4 tunnel for generic usage

> :warning: **Warranty/Disclaimer** <br />
> This is free software and comes with no warranty, as stated in parts 15 and 16 of the GPLv3 license. The creators and contributors of the software are not responsible for how it is used.
> See [License and Support](https://github.com/svpcom/wfb-ng/wiki/License-and-Support) for details.


## Support project
If you like WFB-ng you can support author via:
- https://boosty.to/svpcom/donate
- `bitcoin:bc1qfvlsvr0ea7tzzydngq5cflf4yypemlacgt6t05`

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

### Quick start using Ubuntu Ground Station

- Install patched `RTL8812AU`driver:
```
sudo apt-get install dkms
git clone -b v5.2.20 https://github.com/svpcom/rtl8812au.git
cd rtl8812au/
sudo ./dkms-install.sh
```
- Make sure the driver is correctly installed by running the following command. You should see the WiFi card in an `unmanaged` state. 
```
nmcli
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
- Copy the name of the RTL8812AU WiFi card. 
- Install wfb-ng. Replace `wifi0`with the previously copied name of the WiFi card.
```
git clone -b stable https://github.com/svpcom/wfb-ng.git
cd wfb-ng
sudo ./scripts/install_gs.sh wifi0
```
- Done! To monitor the link use the following command on the ground station:
```
wfb-cli gs
```


**Failing to get connection?**

Make sure the WiFi channel on the ground and on the drone are the same. To check, use:
```
head /etc/wifibroadcast.cfg
```

You should see output similar to:
```
[common]
wifi_channel = 161     # 161 -- radio channel @5825 MHz, range: 5815–5835 MHz, width 20MHz
                       # 1 -- radio channel @2412 Mhz, 
                       # see https://en.wikipedia.org/wiki/List_of_WLAN_channels for reference
```
Ensure the WiFi channel selected is the same on the ground and on the drone.

---


## FAQ
**Q: What type of data can be transmitted using WFB-NG?**

**A:** Any UDP with packet size <= 1445. For example x264 inside RTP or Mavlink.

**Q: What are transmission guarantees?**

**A:** Wifibrodcast uses FEC (forward error correction) which can recover 4 lost packets from 12 packets block with default settings. You can tune it (both TX and RX simultaneously!) to fit your needs.

**Q: Is only Raspberry PI supported?**

**A:** WFB-NG is not tied to any GPU - it operates with UDP packets. But to get RTP stream you need a video encoder (which encodes raw data from camera to x264 stream). In my case RPI is only used for video encoding (because RPI Zero is too slow to do anything else) and all other tasks (including WFB-NG) are done by other board (NanoPI NEO2).

**Q: What is a difference from original wifibroadcast?**

**A:** Original version of wifibroadcast uses a byte-stream as input and splits it to packets of fixed size (1024 by default). If radio packets were lost and this is not corrected by FEC you'll get a hole at random (unexpected) place of stream. This is especially bad if data protocol is not resistant to (was not desired for) such random erasures. So i've rewritten it to use UDP as data source and pack one source UDP packet into one radio packet. Radio packets now have variable size depending on payload size. This reduces video latency a lot.

## Theory
WFB-NG puts the wifi cards into monitor mode. This mode allows to send and receive arbitrary packets without association and waiting for ACK packets.
[Analysis of Injection Capabilities and Media Access of IEEE 802.11 Hardware in Monitor Mode](https://github.com/svpcom/wfb-ng/blob/master/doc/Analysis%20of%20Injection%20Capabilities%20and%20Media%20Access%20of%20IEEE%20802.11%20Hardware%20in%20Monitor%20Mode.pdf)
[802.11 timings](https://github.com/ewa/802.11-data)

Sample usage chain:
-------------------
```
Camera -> gstreamer --[RTP stream (UDP)]--> wfb_tx --//--[ RADIO ]--//--> wfb_rx --[RTP stream (UDP)]--> gstreamer --> Display
```

For encoding logitech c920 camera:
```
gst-launch-1.0 uvch264src device=/dev/video0 initial-bitrate=6000000 average-bitrate=6000000 iframe-period=1000 name=src auto-start=true \
               src.vidsrc ! queue ! video/x-h264,width=1920,height=1080,framerate=30/1 ! h264parse ! rtph264pay ! udpsink host=localhost port=5600
```

To encode a Raspberry Pi Camera V2:
```
raspivid -n  -ex fixedfps -w 960 -h 540 -b 4000000 -fps 30 -vf -hf -t 0 -o - | \
               gst-launch-1.0 -v fdsrc ! h264parse ! rtph264pay config-interval=1 pt=35 ! udpsink sync=false host=127.0.0.1 port=5600
```

To decode:
```
 gst-launch-1.0 udpsrc port=5600 caps='application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264' \
               ! rtph264depay ! avdec_h264 ! clockoverlay valignment=bottom ! autovideosink fps-update-interval=1000 sync=false
```

HOWTO build:
----------------------
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
sudo apt install python3-all libpcap-dev libsodium-dev python3-pip python3-pyroute2 \
            python3-future python3-twisted python3-serial python3-all-dev iw virtualenv \
            debhelper dh-python build-essential -y
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

Supported WiFi hardware:
------------------------
My primary hardware target is Realtek **RTL8812au**. 802.11ac capable. Easy to buy. [**Requires external patched driver!**](https://github.com/svpcom/rtl8812au)  System was tested with ALPHA AWUS036ACH on both sides in 5GHz mode.


Wiki:
-----
See https://github.com/svpcom/wfb-ng/wiki for additional info

Community support:
---------------
Telegram group: (**wfb-ng support**) https://t.me/wfb_ng
Please note, that it is only one official group.
