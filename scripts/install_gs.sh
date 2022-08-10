#!/bin/sh
set -e

# Install required packages
apt update
apt upgrade

apt install python3-all libpcap-dev libsodium-dev python3-pip python3-pyroute2 python3-future python3-twisted python3-serial iw
apt install virtualenv
apt install debhelper
apt install dh-python build-essential

# Build
make deb

# Create key and copy to right location
./wfb_keygen
mv gs.key /etc/gs.key

# Install
dpkg -i deb_dist/*.deb 

# Setup config
cat <<EOT >> /etc/wifibroadcast.cfg
[common]
wifi_channel = 161     # 161 -- radio channel @5825 MHz, range: 5815–5835 MHz, width 20MHz
                       # 1 -- radio channel @2412 Mhz, 
                       # see https://en.wikipedia.org/wiki/List_of_WLAN_channels for reference
wifi_region = 'BO'     # Your country for CRDA (use BO or GY if you want max tx power)  

[gs_mavlink]
peer = 'connect://127.0.0.1:14550'  # outgoing connection
# peer = 'listen://0.0.0.0:14550'   # incoming connection

[gs_video]
peer = 'connect://127.0.0.1:5600'  # outgoing connection for
                                   # video sink (QGroundControl on GS)
EOT

rm /etc/default/wifibroadcast
cat <<EOT >> /etc/default/wifibroadcast
WFB_NICS="$1"
EOT

cat <<EOT >> /etc/NetworkManager/NetworkManager.conf
[keyfile]
unmanaged-devices=interface-name:$1
EOT

FILE=/etc/dhcpcd.conf
if [ -f "$FILE" ]; then
cat <<EOT >> /etc/dhcpcd.conf
denyinterfaces $1
EOT
fi

# Start gs service
systemctl daemon-reload
systemctl start wifibroadcast@gs

echo "Started wfg-ng@gs"
