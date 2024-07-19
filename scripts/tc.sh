#!/bin/bash
wlan=$1

### This is sample script for traffic shaping

# Assumptions: MCS1 for all links
# For different MCS you need to recalculate max total bandwidth and max bandwidth for each stream

#### Set in the wifibroadcast.cfg:

## [base]
## use_qdisc=True

## [drone_video]
## fwmark=1

## [drone_mavlink]
## fwmark=10

## [drone_tunnel]
## fwmark=20

## [gs_mavlink]
## fwmark=10

## [gs_tunnel]
## fwmark=20

# cleanup
tc qdisc del dev $wlan root

# root qdisc
tc qdisc add dev $wlan handle 1 root htb default 100
tc class add dev $wlan parent 1: classid 1:99 htb rate 8mbit

#default class for unclassified traffic (should empty in normal conditions)
tc class add dev $wlan parent 1:99 classid 1:100 htb rate 1kbit ceil 1mbit prio 100 quantum 1000
tc qdisc add dev $wlan handle 100: parent 1:100 pfifo

# video
tc class add dev $wlan parent 1:99 classid 1:1 htb rate 6.5mbit ceil 7mbit prio 2
tc filter add dev $wlan parent 1: handle 1 fw classid 1:1 # data
tc filter add dev $wlan parent 1: handle 2 fw classid 1:1 # fec

# mavlink
tc class add dev $wlan parent 1:99 classid 1:10 htb rate 500kbit ceil 1mbit prio 1
tc filter add dev $wlan parent 1: handle 10 fw classid 1:10 # data
tc filter add dev $wlan parent 1: handle 11 fw classid 1:10 # fec

# tunnel
tc class add dev $wlan parent 1:99 classid 1:20 htb rate 500kbit ceil 1mbit prio 3
tc filter add dev $wlan parent 1: handle 20 fw classid 1:20 # data
tc filter add dev $wlan parent 1: handle 21 fw classid 1:20 # fec

# qdisc
tc qdisc add dev $wlan handle 101: parent 1:1 pfifo    # video
tc qdisc add dev $wlan handle 102: parent 1:10 pfifo   # mavlink
tc qdisc add dev $wlan handle 103: parent 1:20 pfifo   # tunnel
