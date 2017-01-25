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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <assert.h>

#include <string>
#include <memory>

extern "C"
{
#include "fec.h"
}

#include "wifibroadcast.hpp"
#include "tx.hpp"


Transmitter::Transmitter(const char *wlan, int k, int n, uint8_t radio_rate, uint8_t radio_port) : wlan(wlan), fec_k(k), fec_n(n), block_idx(0),
                                                                                                   fragment_idx(0), seq(0), radio_rate(radio_rate),
                                                                                                   radio_port(radio_port), max_packet_size(0)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    ppcap = pcap_create(wlan, errbuf);
    if (ppcap == NULL){
        throw runtime_error(string_format("Unable to open interface %s in pcap: %s", wlan, errbuf));
    }
    if (pcap_set_snaplen(ppcap, 4096) !=0) throw runtime_error("set_snaplen failed");
    if (pcap_set_promisc(ppcap, 1) != 0) throw runtime_error("set_promisc failed");
    //if (pcap_set_rfmon(ppcap, 1) !=0) throw runtime_error("set_rfmon failed");
    if (pcap_set_timeout(ppcap, -1) !=0) throw runtime_error("set_timeout failed");
    //if (pcap_set_buffer_size(ppcap, 2048) !=0) throw runtime_error("set_buffer_size failed");
    if (pcap_activate(ppcap) !=0) throw runtime_error(string_format("pcap_activate failed: %s", pcap_geterr(ppcap)));
    //if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw runtime_error(string_format("set_nonblock failed: %s", errbuf));

    fec_p = fec_new(fec_k, fec_n);

    block = new uint8_t*[fec_n];
    for(int i=0; i < fec_n; i++)
    {
        block[i] = new uint8_t[MAX_FEC_PAYLOAD];
    }
}

Transmitter::~Transmitter()
{
    for(int i=0; i < fec_n; i++)
    {
        delete block[i];
    }
    delete block;

    fec_free(fec_p);
    pcap_close(ppcap);
}


void Transmitter::send_block_fragment(size_t packet_size)
{
    uint8_t txbuf[MAX_PACKET_SIZE];
    uint8_t *p = txbuf;
    wblock_hdr_t block_hdr;
    block_hdr.block_idx = block_idx;
    block_hdr.fragment_idx = fragment_idx;

    memcpy(p, radiotap_header, sizeof(radiotap_header));
    p[8] = radio_rate * 2;
    p += sizeof(radiotap_header);
    memcpy(p, ieee80211_header, sizeof(ieee80211_header));
    p[SRC_MAC_LASTBYTE] = radio_port;
    p[DST_MAC_LASTBYTE] = radio_port;
    p += sizeof(ieee80211_header);
    memcpy(p, &block_hdr, sizeof(block_hdr));
    p += sizeof(block_hdr);
    memcpy(p, block[fragment_idx], packet_size);
    p += packet_size;

    if (pcap_inject(ppcap, txbuf, p - txbuf) != p - txbuf)
    {
        throw runtime_error(string_format("Unable to inject packet"));
    }
}

void Transmitter::send_packet(const uint8_t *buf, size_t size)
{
    wpacket_hdr_t packet_hdr;

    packet_hdr.seq = seq++;
    packet_hdr.packet_size = size;
    memset(block[fragment_idx], '\0', MAX_FEC_PAYLOAD);
    memcpy(block[fragment_idx], &packet_hdr, sizeof(packet_hdr));
    memcpy(block[fragment_idx] + sizeof(packet_hdr), buf, size);
    send_block_fragment(sizeof(packet_hdr) + size);
    max_packet_size = max(max_packet_size, sizeof(packet_hdr) + size);
    fragment_idx += 1;

    if (fragment_idx < fec_k)  return;

    fec_encode(fec_p, (const uint8_t**)block, block + fec_k, max_packet_size);
    while (fragment_idx < fec_n)
    {
        send_block_fragment(max_packet_size);
        fragment_idx += 1;
    }
    block_idx += 1;
    fragment_idx = 0;
    max_packet_size = 0;
}


int open_udp_socket(int port)
{
    struct sockaddr_in saddr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) throw runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

    bzero((char *) &saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        throw runtime_error(string_format("Bind error: %s", strerror(errno)));
    }
    return fd;
}

int main(int argc, char * const *argv)
{
    uint8_t buf[MAX_PAYLOAD_SIZE];

    int opt;
    uint8_t k=8, n=12, radio_port=1, radio_rate=54;
    int udp_port=5600;

    while ((opt = getopt(argc, argv, "k:n:u:r:p:")) != -1) {
        switch (opt) {
        case 'k':
            k = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'u':
            udp_port = atoi(optarg);
            break;
        case 'r':
            radio_rate = atoi(optarg);
            break;
        case 'p':
            radio_port = atoi(optarg);
            break;
        default: /* '?' */
        show_usage:
            fprintf(stderr, "Usage: %s [-k RS_K] [-n RS_N] [-u udp_port] [-r tx_rate] [-p radio_port] interface\n",
                    argv[0]);
            fprintf(stderr, "Default: k=%d, n=%d, udp_port=%d, tx_rate=%d Mbit/s, radio_port=%d\n", k, n, udp_port, radio_rate, radio_port);
            fprintf(stderr, "Radio MTU: %ld\n", MAX_PAYLOAD_SIZE);
            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    try
    {
        int fd = open_udp_socket(udp_port);
        Transmitter t(argv[optind], k, n, radio_rate, radio_port);

        for(;;)
        {
            ssize_t rsize = recv(fd, buf, sizeof(buf), 0);
            if (rsize < 0) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
            t.send_packet(buf, rsize);
        }
        return 0;
    }catch(runtime_error e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
}
