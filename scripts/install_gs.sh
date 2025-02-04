#!/bin/bash
set -e

nics="$*"
auto_nics=0
release=master

if [ -z "$nics" ]
then
    nics="$($(dirname $0)/wfb-nics)"
    auto_nics=1
fi

if [ -z "$nics" ]
then
    echo "No supported wifi adapters found, please connect them and setup drivers first"
    echo "For 8812au: https://github.com/svpcom/rtl8812au"
    echo "For 8812eu: https://github.com/svpcom/rtl8812eu"
    exit 1
fi

# Try to install prebuilt packages from wfb-ng apt repository

curl -s https://apt.wfb-ng.org/public.asc | sudo gpg --dearmor --yes -o /usr/share/keyrings/wfb-ng.gpg
echo "deb [signed-by=/usr/share/keyrings/wfb-ng.gpg] https://apt.wfb-ng.org/ $(lsb_release -cs) $release" | sudo tee /etc/apt/sources.list.d/wfb-ng.list
sudo apt update

if ! sudo apt -y install wfb-ng
then
    # Install required packages for wfb-ng source build

    apt -y install python3-all python3-all-dev libpcap-dev libsodium-dev libevent-dev python3-pip python3-pyroute2 python3-msgpack \
       python3-future python3-twisted python3-serial python3-jinja2 iw virtualenv debhelper dh-python fakeroot build-essential

    tmpdir="$(mktemp -d)"
    git clone -b $release --depth 1 https://github.com/svpcom/wfb-ng.git "$tmpdir"

    (cd "$tmpdir" && make deb && sudo apt -y install ./deb_dist/*.deb)
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
cat <<EOF >> /etc/wifibroadcast.cfg
[common]
wifi_channel = 165     # 165 -- radio channel @5825 MHz, range: 5815–5835 MHz, width 20MHz
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
    echo "denyinterfaces $(nics)" >> /etc/dhcpcd.conf
fi

# Start gs service
systemctl daemon-reload
systemctl start wifibroadcast@gs
systemctl status wifibroadcast@gs
systemctl enable wifibroadcast@gs

echo "GS setup successfully finished"
