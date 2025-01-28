#!/bin/bash
set -e

_cleanup()
{
    systemctl stop wifibroadcast@gs_bind
    systemctl start wifibroadcast@gs
}

if ! [ -f /etc/gs.key ]
then
    tmpdir=$(mktemp -d)
    (cd $tmpdir && wfb_keygen)
    mv $tmpdir/{gs,drone}.key /etc
    rmdir $tmpdir
fi

if ! [ -f /etc/bind.key ]
then
    # Default bind key
    echo "OoLVgEYyFofg9zdhfYPks8/L8fqWaF9Jk8aEnynFPsXNqhSpRCMbVKBFP4fCEOv5DGcbXmUHV5eSykAbFB70ew==" | base64 -d > /etc/bind.key
fi

if ! [ -f /etc/wifibroadcast.cfg ]
then
    cat > /etc/wifibroadcast.cfg <<EOF
[common]
link_domain = 'auto_$(tr -dc 0-9 < /dev/urandom | head -c8)'
wifi_channel = 165     # 165 -- radio channel @5825 MHz, range: 5815–5835 MHz, width 20MHz
                       # see https://en.wikipedia.org/wiki/List_of_WLAN_channels for reference

wifi_region = 'BO'     # Your country for CRDA (use BO or GY if you want max tx power)

[gs_mavlink]
peer = 'connect://127.0.0.1:14550'  # mavlink connection to QGC

[gs_video]
peer = 'connect://127.0.0.1:5600'  # outgoing connection for
                                   # video sink (QGroundControl on GS)

EOF
fi

if ! [ -f /etc/bind.yaml ]
then
    wfb-server --gen-bind-yaml --profiles drone drone_bind > /etc/bind.yaml
fi

trap _cleanup EXIT

systemctl stop wifibroadcast@gs
systemctl start wifibroadcast@gs_bind

for i in $(seq 10)
do
    if ip -4 addr show dev gs-bind > /dev/null 2>&1
    then
        break
    fi
    sleep 1
done

if ! ip -4 addr show dev gs-bind > /dev/null 2>&1
then
    echo "Unable to start binding tunnel"
    exit 1
fi

echo "Connecting to drone..."
socat -d TCP4:10.5.99.2:5555,crlf,retry=30,interval=1 EXEC:/usr/bin/wfb_bind_client.sh

