#!/bin/bash

WLAN=$1
CHANNEL5G="149"

echo "Setting $WLAN to channel $CHANNEL5G"
ifconfig $WLAN down
iw reg set BO
iw dev $WLAN set monitor otherbss
ifconfig $WLAN up
iwconfig $WLAN channel $CHANNEL5G

./tx $WLAN
