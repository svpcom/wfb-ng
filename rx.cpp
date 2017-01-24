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
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C"
{
#include "ieee80211_radiotap.h"
#include "fec.h"
}

#include <string>
#include <memory>

#include "wifibroadcast.hpp"
#include "rx.hpp"


Receiver::Receiver(const char *wlan, int radio_port, Aggregator *agg) : agg(agg)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    ppcap = pcap_create(wlan, errbuf);

    if (ppcap == NULL){
        throw runtime_error(string_format("Unable to open interface %s in pcap: %s\n", wlan, errbuf));
    }

    if (pcap_set_snaplen(ppcap, 2048) !=0) throw runtime_error("set_snaplen failed");
    if (pcap_set_promisc(ppcap, 1) != 0) throw runtime_error("set_promisc failed");
    if (pcap_set_rfmon(ppcap, 1) !=0) throw runtime_error("set_rfmon failed");
    if (pcap_set_timeout(ppcap, -1) !=0) throw runtime_error("set_timeout failed");
    //if (pcap_set_buffer_size(ppcap, 2048) !=0) throw runtime_error("set_buffer_size failed");
    if (pcap_activate(ppcap) !=0) throw runtime_error(string_format("pcap_activate failed: %s", pcap_geterr(ppcap)));
    if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw runtime_error(string_format("set_nonblock failed: %s", errbuf));

    int link_encap = pcap_datalink(ppcap);
    struct bpf_program bpfprogram;
    string program;

    switch (link_encap)
    {
    case DLT_PRISM_HEADER:
        fprintf(stderr, "%s has DLT_PRISM_HEADER Encap\n", wlan);
        program = string_format("radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", radio_port);
        break;

    case DLT_IEEE802_11_RADIO:
        fprintf(stderr, "%s has DLT_IEEE802_11_RADIO Encap\n", wlan);
        program = string_format("ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", radio_port);
        break;

    default:
        throw runtime_error(string_format("unknown encapsulation on %s", wlan));
    }

    if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
        throw runtime_error(string_format("Unable to compile %s: %s", program, pcap_geterr(ppcap)));
    }

    if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
        throw runtime_error(string_format("Unable to set filter %s: %s", program, pcap_geterr(ppcap)));
    }

    pcap_freecode(&bpfprogram);
    fd = pcap_get_selectable_fd(ppcap);
}


Receiver::~Receiver()
{
    close(fd);
    pcap_close(ppcap);
}


void Receiver::loop_iter(void)
{
    struct pcap_pkthdr hdr;
    const uint8_t* pkt = pcap_next(ppcap, &hdr);

    if (pkt == NULL) {
        return;
    }

    int pktlen = hdr.caplen;
    int pkt_rate = 0, antenna = 0, pwr = 0;
    uint8_t flags = 0;
    struct ieee80211_radiotap_iterator iterator;
    int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header*)pkt, pktlen, NULL);

    while (ret == 0) {
        ret = ieee80211_radiotap_iterator_next(&iterator);

        if (ret)
            continue;

        /* see if this argument is something we can use */

        switch (iterator.this_arg_index)
        {
            /*
             * You must take care when dereferencing iterator.this_arg
             * for multibyte types... the pointer is not aligned.  Use
             * get_unaligned((type *)iterator.this_arg) to dereference
             * iterator.this_arg for type "type" safely on all arches.
             */
        case IEEE80211_RADIOTAP_RATE:
            /* radiotap "rate" u8 is in
             * 500kbps units, eg, 0x02=1Mbps
             */
            pkt_rate = (*(uint8_t*)(iterator.this_arg))/2;
            break;

        case IEEE80211_RADIOTAP_ANTENNA:
            antenna = *(uint8_t*)(iterator.this_arg);
            break;

        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            pwr = *(int8_t*)(iterator.this_arg);
            break;

        case IEEE80211_RADIOTAP_FLAGS:
            flags = *(uint8_t*)(iterator.this_arg);
            break;

        default:
            break;
        }
    }  /* while more rt headers */

    if (ret != -ENOENT){
        fprintf(stderr, "Error parsing radiotap header!\n");
        return;
    }

    if (flags & IEEE80211_RADIOTAP_F_FCS)
    {
        pktlen -= 4;
    }

    if (flags & IEEE80211_RADIOTAP_F_BADFCS)
    {
        fprintf(stderr, "Got packet with bad fsc\n");
        return;
    }

    /* discard the radiotap header part */
    pkt += iterator._max_length;
    pktlen -= iterator._max_length;

    //printf("%d mbit/s ant %d %ddBm size:%d\n", pkt_rate, antenna, pwr, pktlen);

    if (pktlen > sizeof_ieee80211_header)
    {
        agg->process_packet(pkt + sizeof_ieee80211_header, pktlen - sizeof_ieee80211_header);
    } else {
        fprintf(stderr, "short packet (ieee header)\n");
        return;
    }
}


Aggregator::Aggregator(const string &client_addr, int client_port, int k, int n) : fec_k(k), fec_n(n), block_idx(0), send_fragment_idx(0), seq(0), has_fragments(0), fragment_lost(false)
{
    sockfd = open_udp_socket(client_addr, client_port);
    fec_p = fec_new(fec_k, fec_n);

    fragments = new uint8_t*[fec_n];
    for(int i=0; i < fec_n; i++)
    {
        fragments[i] = new uint8_t[MAX_FEC_PAYLOAD];
    }

    fragment_map = new uint8_t[fec_n];
    memset(fragment_map, '\0', fec_n * sizeof(uint8_t));
}


Aggregator::~Aggregator()
{
    delete fragment_map;

    for(int i=0; i < fec_n; i++)
    {
        delete fragments[i];
    }
    delete fragments;

    close(sockfd);
}


int Aggregator::open_udp_socket(const string &client_addr, int client_port)
{
    struct sockaddr_in saddr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) throw runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    bzero((char *) &saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
    saddr.sin_port = htons((unsigned short)client_port);

    if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        throw runtime_error(string_format("Connect error: %s", strerror(errno)));
    }
    return fd;
}


void Aggregator::process_packet(const uint8_t *buf, size_t size)
{
    if(size < sizeof(wblock_hdr_t) + sizeof(wpacket_hdr_t))
    {
        fprintf(stderr, "short packet (fec header)\n");
        return;
    }

    if (size > MAX_FEC_PAYLOAD + sizeof(wblock_hdr_t))
    {
        fprintf(stderr, "long packet (fec payload)\n");
        return;
    }

    wblock_hdr_t *block_hdr = (wblock_hdr_t*)buf;

    if (block_hdr->block_idx != block_idx)
    {
        if(has_fragments < fec_k)
        {
            for(int i = send_fragment_idx; i < fec_k; i++)
            {
                if (fragment_map[i]) send_packet(i);
            }
        }
        block_idx = block_hdr->block_idx;
        has_fragments = 0;
        send_fragment_idx = 0;
        fragment_lost = false;
        memset(fragment_map, '\0', fec_n * sizeof(uint8_t));
    }

    if (has_fragments >= fec_k || fragment_map[block_hdr->fragment_idx]) return;

    memset(fragments[block_hdr->fragment_idx], '\0', MAX_FEC_PAYLOAD);
    memcpy(fragments[block_hdr->fragment_idx],  buf + sizeof(wblock_hdr_t), size - sizeof(wblock_hdr_t));
    fragment_map[block_hdr->fragment_idx] = 1;
    has_fragments += 1;

    if(block_hdr->fragment_idx > 0 && !fragment_map[block_hdr->fragment_idx - 1])
    {
        fragment_lost = true;
    }

    if(!fragment_lost)
    {
        send_packet(send_fragment_idx);
        send_fragment_idx += 1;
    }

    if(has_fragments == fec_k)
    {
        apply_fec();
        for(int i = send_fragment_idx; i < fec_k; i++)
        {
            send_packet(i);
        }
    }
}

void Aggregator::send_packet(int idx)
{
    wpacket_hdr_t* packet_hdr = (wpacket_hdr_t*)(fragments[idx]);
    uint8_t *payload = (fragments[idx]) + sizeof(wpacket_hdr_t);

    if (packet_hdr->seq > seq + 1)
    {
        fprintf(stderr, "%d packets lost\n", packet_hdr->seq - seq - 1);
    }

    seq = packet_hdr->seq;

    if(packet_hdr->packet_size > MAX_PAYLOAD_SIZE)
    {
        fprintf(stderr, "corrupted packet %d\n", seq);
    }else{
        send(sockfd, payload, packet_hdr->packet_size, 0);
    }
}

void Aggregator::apply_fec(void)
{
    unsigned index[fec_k];
    uint8_t *in_blocks[fec_k];
    uint8_t *out_blocks[fec_n - fec_k];
    int j = fec_k;
    int ob_idx = 0;

    for(int i=0; i < fec_k; i++)
    {
        if(fragment_map[i])
        {
            in_blocks[i] = fragments[i];
            index[i] = i;
        }else
        {
            for(;j < fec_n; j++)
            {
                if(fragment_map[j])
                {
                    in_blocks[i] = fragments[j];
                    out_blocks[ob_idx++] = fragments[i];
                    index[i] = j;
                    j++;
                    break;
                }
            }
        }
    }
    fec_decode(fec_p, (const uint8_t**)in_blocks, out_blocks, index, MAX_FEC_PAYLOAD);
}

int main(int argc, char* const *argv)
{
    int opt;
    uint8_t k=8, n=12, radio_port=1;
    int client_port=5600;
    string client_addr="127.0.0.1";

    while ((opt = getopt(argc, argv, "k:n:c:u:p:")) != -1) {
        switch (opt) {
        case 'k':
            k = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'c':
            client_addr = string(optarg);
            break;
        case 'u':
            client_port = atoi(optarg);
            break;
        case 'p':
            radio_port = atoi(optarg);
            break;
        default: /* '?' */
        show_usage:
            fprintf(stderr, "Usage: %s [-k RS_K] [-n RS_N] [-c client_addr] [-u client_port] [-p radio_port] interface1 [interface2] ...\n",
                    argv[0]);
            fprintf(stderr, "Default: k=%d, n=%d, connect=%s:%d, radio_port=%d\n", k, n, client_addr.c_str(), client_port, radio_port);
            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    int nfds = min(argc - optind, MAX_RX_INTERFACES);
    struct pollfd fds[MAX_RX_INTERFACES];
    Receiver* rx[MAX_RX_INTERFACES];

    try
    {
        Aggregator agg(client_addr, client_port, k, n);

        memset(fds, '\0', sizeof(fds));

        for(int i = 0; i < nfds; i++)
        {
            rx[i] = new Receiver(argv[optind + i], radio_port, &agg);
            fds[i].fd = rx[i]->getfd();
            fds[i].events = POLLIN;
        }

        while(1)
        {
            int rc = poll(fds, nfds, 1000);
            if (rc < 0) throw runtime_error(string_format("Poll error: %s", strerror(errno)));
            for(int i = 0; rc > 0 && i < nfds; i++)
            {
                if (fds[i].revents & POLLERR)
                {
                    throw runtime_error("socket error!");
                }
                if (fds[i].revents & POLLIN){
                    rx[i]->loop_iter();
                    rc -= 1;
                }
            }
        }
    }catch(runtime_error e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
