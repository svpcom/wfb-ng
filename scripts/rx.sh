#!/bin/bash

WLANS=$@
CHANNEL5G="149"

for WLAN in $WLANS
do
echo "Setting $WLAN to channel $CHANNEL5G"
ifconfig $WLAN down
iw dev $WLAN set monitor otherbss
iw reg set BO
ifconfig $WLAN up
iwconfig $WLAN channel $CHANNEL5G
done

./rx $WLANS
