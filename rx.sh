#!/bin/bash

WLANS=$@
#CHANNEL5G="6"
CHANNEL5G="149"

for WLAN in $WLANS
do
echo "Setting $WLAN to channel $CHANNEL5G"
ifconfig $WLAN down
iw dev $WLAN set monitor otherbss fcsfail
iw reg set BO
ifconfig $WLAN up
iwconfig $WLAN channel $CHANNEL5G
done

./rx -u 5600 $WLANS
#tcpdump -i $WLAN 'ether[0x0a:4]==0x13223344' 
