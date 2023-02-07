#!/bin/bash

####
#### WARNING!!!
#### This script is depricated and **not supported** by author!
#### I leave it only for reference for **developers**.
#### Use python services instead.
####


WLAN=$1

BAND="5G"
#BAND="2G"

CHANNEL2G="6"
CHANNEL5G="149"

nmcli device set $WLAN managed no
ip link set $WLAN down
iw dev $WLAN set monitor otherbss
iw reg set BO
ip link set $WLAN up

case $BAND in
  "5G")
      echo "Setting $WLAN to channel $CHANNEL5G"
      iw dev $WLAN set channel $CHANNEL5G HT20
      ;;
  "2G")
      echo "Setting $WLAN to channel $CHANNEL2G"
      iw dev $WLAN set channel $CHANNEL2G HT20
      ;;
   *)
      echo "Select 2G or 5G band"
      exit -1;
      ;;
esac

# Video TX
./wfb_tx -p 0 -u 5602 -K drone.key $WLAN
