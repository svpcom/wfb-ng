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

using namespace std;


class Transmitter
{
public:
    Transmitter(const char* wlan, int k, int m, uint8_t radio_rate, uint8_t radio_port);
    ~Transmitter();
    void send_packet(const uint8_t *buf, size_t size);

private:
    void send_block_fragment(size_t packet_size);
    string wlan;
    pcap_t *ppcap;
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint8_t block_idx;
    uint8_t fragment_idx;
    uint32_t seq;
    uint8_t radio_rate;
    uint8_t radio_port;
    uint8_t** block;
    size_t max_packet_size;
};
