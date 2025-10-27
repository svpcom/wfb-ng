#!/bin/bash
set -e

nics="$*"
auto_nics=0
release=master

if [ $(id -u) != "0" ]
then
    echo "Root access is required. Run: sudo $0 $*"
    exit 1
fi

err_handler()
{
    echo "--------------------------------------------------------------------------------"
    echo "WFB-ng setup failed"
    exit 1
}

wfb_nics()
{
    for i in $(find /sys/class/net/ -maxdepth 1 -type l | sort)
    do
        if udevadm info $i | grep -qE 'ID_NET_DRIVER=(rtl88xxau_wfb|rtl88x2eu)'
        then
            echo $(basename $i)
        fi
    done
}

if [ -z "$nics" ]
then
    nics="$(wfb_nics)"
    auto_nics=1
fi

if [ -z "$nics" ]
then
    echo "No supported wifi adapters found, please connect them and setup drivers first"
    echo "For 8812au: https://github.com/svpcom/rtl8812au"
    echo "For 8812eu: https://github.com/svpcom/rtl8812eu"
    exit 1
fi

trap err_handler ERR

# Try to install prebuilt packages from wfb-ng apt repository

curl -s https://apt.wfb-ng.org/public.asc | gpg --dearmor --yes -o /usr/share/keyrings/wfb-ng.gpg
echo "deb [signed-by=/usr/share/keyrings/wfb-ng.gpg] https://apt.wfb-ng.org/ $(lsb_release -cs) $release" > /etc/apt/sources.list.d/wfb-ng.list

if ! apt update
then
    rm -f /etc/apt/sources.list.d/wfb-ng.list /usr/share/keyrings/wfb-ng.gpg
    apt update
fi

if ! apt -y install wfb-ng
then
    # Install required packages for wfb-ng source build

    apt -y install python3-all python3-all-dev libpcap-dev libsodium-dev libevent-dev python3-pip python3-pyroute2 python3-msgpack \
       python3-twisted python3-serial python3-jinja2 iw virtualenv debhelper dh-python fakeroot build-essential \
       libgstrtspserver-1.0-dev socat git libcatch2-dev

    tmpdir="$(mktemp -d)"
    git clone -b $release --depth 1 https://github.com/svpcom/wfb-ng.git "$tmpdir"

    (cd "$tmpdir" && make deb CFLAGS="-march=native" && apt -y install ./deb_dist/*.deb)
    rm -rf "$tmpdir"
fi

# Create key and copy to right location
(cd /etc && wfb_keygen)

if [ $auto_nics -eq 0 ]
then
    echo "Saving WFB_NICS=\"$nics\" to /etc/default/wifibroadcast"
    echo "WFB_NICS=\"$nics\"" > /etc/default/wifibroadcast
else
    echo "Using wifi autodetection"
fi

# Setup config
cat <<EOF > /etc/wifibroadcast.cfg
[common]
wifi_channel = 165     # 165 -- radio channel @5825 MHz, range: 5815-5835 MHz, width 20MHz
                       # 1 -- radio channel @2412 Mhz,
                       # see https://en.wikipedia.org/wiki/List_of_WLAN_channels for reference
wifi_region = 'BO'     # Your country for CRDA (use BO or GY if you want max tx power)

[gs_mavlink]
peer = 'connect://127.0.0.1:14550'  # outgoing connection
# peer = 'listen://0.0.0.0:14550'   # incoming connection

[gs_video]
peer = 'connect://127.0.0.1:5600'  # outgoing connection for
                                   # video sink (QGroundControl on GS)
EOF

cat > /etc/modprobe.d/wfb.conf << EOF
# blacklist stock module
blacklist 88XXau
blacklist 8812au
blacklist 8812
options cfg80211 ieee80211_regdom=RU
# maximize output power by default
#options 88XXau_wfb rtw_tx_pwr_idx_override=30
# minimize output power by default
options 88XXau_wfb rtw_tx_pwr_idx_override=1
options 8812eu rtw_tx_pwr_by_rate=0 rtw_tx_pwr_lmt_enable=0
EOF

if [ -f /etc/dhcpcd.conf ]; then
    echo "denyinterfaces $nics" >> /etc/dhcpcd.conf
fi

cat > /etc/motd <<__EOF__
WFB-ng: http://wfb-ng.org
Setup HOWTO: https://github.com/svpcom/wfb-ng/wiki/Setup-HOWTO
Community chat: (wfb-ng support) https://t.me/wfb_ng

Version: $release

Quickstart (x86 laptop):
1. Run "wfb-cli gs" to monitor link state
2. Run QGroundControl

Quickstart (SBC + RTP video):
1. Run "wfb-cli gs" to monitor link state
2. Edit /etc/wifibroadcast.cfg and in section [gs_video] set peer to ip address of your laptop with QGC
3. Edit /etc/wifibroadcast.cfg and in section [gs_mavlink] set peer to ip address of your laptop with QGC
4. Reboot SBC.
5. Run QGroundControl on your laptop

Quickstart (SBC + RTSP video):
1. Run "wfb-cli gs" to monitor link state
2. Run "sudo systemctl enable rtsp@h264" or "sudo systemctl enable rtsp@h265" (according to your video codec)
3. Edit /etc/wifibroadcast.cfg and in section [gs_mavlink] set peer to ip address of your laptop with QGC
4. Reboot SBC.
5. Run QGroundControl on your laptop. Set video QGC source to rtsp://x.x.x.x:8554/wfb , where x.x.x.x is GS IP address.
6. (optional) Run any other RTSP video player(s) for rtsp://x.x.x.x:8554/wfb

To set TX power edit /etc/modprobe.d/wfb.conf and reboot.

In case of any failures check "sudo systemctl status wifibroadcast@gs" service status.
See full logs via: "sudo journalctl -xu wifibroadcast@gs"
__EOF__

# Start gs service
systemctl daemon-reload
systemctl start wifibroadcast@gs
systemctl status wifibroadcast@gs
systemctl enable wifibroadcast@gs

echo "--------------------------------------------------------------------------------"
echo
cat /etc/motd
echo
echo "--------------------------------------------------------------------------------"
echo "GS setup successfully finished"
