#!/bin/bash
set -e

_cleanup()
{
    systemctl stop wifibroadcast@drone_bind
    systemctl start wifibroadcast@drone
}

if ! [ -f /etc/bind.key ]
then
    # Default bind key
    echo "OoLVgEYyFofg9zdhfYPks8/L8fqWaF9Jk8aEnynFPsXNqhSpRCMbVKBFP4fCEOv5DGcbXmUHV5eSykAbFB70ew==" | base64 -d > /etc/bind.key
fi

trap _cleanup EXIT

systemctl stop wifibroadcast@drone
systemctl start wifibroadcast@drone_bind

for i in $(seq 10)
do
    if ip -4 addr show dev drone-bind > /dev/null 2>&1
    then
        break
    fi
    sleep 1
done

if ! ip -4 addr show dev drone-bind > /dev/null 2>&1
then
    echo "Unable to start binding tunnel"
    exit 1
fi

echo "Waiting for binding request..."
socat -d TCP4-LISTEN:5555,bind=10.5.99.2,reuseaddr,crlf EXEC:/usr/bin/wfb_bind_server.sh
