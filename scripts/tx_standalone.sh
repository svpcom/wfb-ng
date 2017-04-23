#!/bin/bash

WLAN=$1
CHANNEL5G="149"

echo "Setting $WLAN to channel $CHANNEL5G"
ifconfig $WLAN down
iw dev $WLAN set monitor otherbss
iw reg set BO
ifconfig $WLAN up
iw dev $WLAN set bitrates ht-mcs-5 1 sgi-5
iw dev $WLAN set channel $CHANNEL5G HT40+

./tx $WLAN
