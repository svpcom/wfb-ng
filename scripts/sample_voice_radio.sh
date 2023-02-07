#!/bin/bash

####
#### Sample packet voice radio
####


WLAN=$1

BAND="5G"
#BAND="2G"

CHANNEL2G="6"
CHANNEL5G="149"

trap 'kill 0' SIGINT

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

# Audio TX/RX
./wfb_tx -p 0 -k 1 -n 2 -u 5602 -K drone.key $WLAN &
./wfb_rx -p 0 -u 5600 -K gs.key $WLAN &
gst-launch-1.0 autoaudiosrc is-live=true ! 'audio/x-raw,rate=8000,channels=1' ! removesilence hysteresis=1000 remove=true ! \
               audioconvert ! rtpL16pay mtu=1400 min-ptime=100000000 ! \
               udpsink  host=127.0.0.1 port=5602 sync=false &
gst-launch-1.0 udpsrc port=5600 caps='application/x-rtp, media=(string)audio, clock-rate=(int)8000, encoding-name=(string)L16, encoding-params=(string)1, channels=(int)1, payload=(int)96' \
               ! rtpL16depay  ! autoaudiosink &
wait
