// -*- C++ -*-
//
// Copyright (C) 2017 Vasily Evseenko <svpcom@p2ptech.org>
// based on wifibroadcast (c)2015 befinitiv

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define sizeof_ieee80211_header 24

class Aggregator
{
public:
    Aggregator(const string &client_addr, int client_port, int k, int n);
    ~Aggregator();
    void process_packet(const uint8_t *buf, size_t size);
private:
    int open_udp_socket(const string &client_addr, int client_port);
    void apply_fec(void);
    void send_packet(int idx);
    int sockfd;
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint8_t block_idx;
    uint8_t send_fragment_idx;
    uint32_t seq;
    uint8_t** fragments;
    uint8_t *fragment_map;
    uint8_t has_fragments;
    bool fragment_lost;
};

class Receiver
{
public:
    Receiver(const char* wlan, int port, Aggregator* agg);
    ~Receiver();
    void loop_iter(void);
    int getfd(void){ return fd; }
private:
    Aggregator *agg;
    int fd;
    pcap_t *ppcap;
};
