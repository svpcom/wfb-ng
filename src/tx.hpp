// -*- C++ -*-
//
// Copyright (C) 2017 - 2024 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
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

#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <string>
#include <vector>
#include <string.h>
#include "fec.h"
#include "wifibroadcast.hpp"
#include <stdexcept>

class Transmitter
{
public:
    Transmitter(int k, int m, const std::string &keypair, uint64_t epoch, uint32_t channel_id);
    virtual ~Transmitter();
    bool send_packet(const uint8_t *buf, size_t size, uint8_t flags);
    void send_session_key(void);
    virtual void select_output(int idx) = 0;
    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected, uint32_t &dropped) = 0;
protected:
    virtual void inject_packet(const uint8_t *buf, size_t size) = 0;

private:
    void send_block_fragment(size_t packet_size);
    void make_session_key(void);

    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint64_t block_idx; // (block_idx << 8) + fragment_idx = nonce (64bit)
    uint8_t fragment_idx;
    uint8_t** block;
    size_t max_packet_size;
    const uint64_t epoch; // Packets from old epoch will be discarded
    const uint32_t channel_id; // (link_id << 8) + port_number

    // tx->rx keypair
    uint8_t tx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t rx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];
    uint8_t session_key_packet[sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES];
};

class txAntennaItem
{
public:
    txAntennaItem(void) : count_injected(0), count_dropped(0), latency_sum(0), latency_min(0), latency_max(0) {}

    void log_latency(uint64_t latency, bool succeeded) {
        if(count_injected + count_dropped == 0)
        {
            latency_min = latency;
            latency_max = latency;
        } else {
            latency_min = std::min(latency, latency_min);
            latency_max = std::max(latency, latency_max);
        }

        latency_sum += latency;

        if (succeeded) count_injected += 1;
        else count_dropped += 1;
    }

    uint32_t count_injected;
    uint32_t count_dropped;
    uint64_t latency_sum;
    uint64_t latency_min;
    uint64_t latency_max;
};

typedef std::unordered_map<uint64_t, txAntennaItem> tx_antenna_stat_t;

class RawSocketTransmitter : public Transmitter
{
public:
    RawSocketTransmitter(int k, int m, const std::string &keypair, uint64_t epoch, uint32_t channel_id, const std::vector<std::string> &wlans);
    virtual ~RawSocketTransmitter();
    virtual void select_output(int idx) { current_output = idx; }
    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected, uint32_t &dropped);
private:
    virtual void inject_packet(const uint8_t *buf, size_t size);
    const uint32_t channel_id;
    int current_output;
    uint16_t ieee80211_seq;
    std::vector<int> sockfds;
    tx_antenna_stat_t antenna_stat;
};


class UdpTransmitter : public Transmitter
{
public:
    UdpTransmitter(int k, int m, const std::string &keypair, const std::string &client_addr, int base_port, uint64_t epoch, uint32_t channel_id): \
        Transmitter(k, m, keypair, epoch, channel_id),                  \
        base_port(base_port)
    {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short)base_port);
    }

    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected, uint32_t &dropped) {}

    virtual ~UdpTransmitter()
    {
        close(sockfd);
    }

    virtual void select_output(int idx)
    {
        assert(idx >= 0);
        saddr.sin_port = htons((unsigned short)(base_port + idx));
    }

private:
    virtual void inject_packet(const uint8_t *buf, size_t size)
    {
        assert(size <= MAX_FORWARDER_PACKET_SIZE);
        wrxfwd_t fwd_hdr = { .wlan_idx = (uint8_t)(rand() % 2) };

        memset(fwd_hdr.antenna, 0xff, sizeof(fwd_hdr.antenna));
        memset(fwd_hdr.rssi, SCHAR_MIN, sizeof(fwd_hdr.rssi));

        fwd_hdr.antenna[0] = (uint8_t)(rand() % 2);
        fwd_hdr.rssi[0] = (int8_t)(rand() & 0xff);

        struct iovec iov[2] = {{ .iov_base = (void*)&fwd_hdr,
                                 .iov_len = sizeof(fwd_hdr)},
                               { .iov_base = (void*)buf,
                                 .iov_len = size }};

        struct msghdr msghdr = { .msg_name = &saddr,
                                 .msg_namelen = sizeof(saddr),
                                 .msg_iov = iov,
                                 .msg_iovlen = 2,
                                 .msg_control = NULL,
                                 .msg_controllen = 0,
                                 .msg_flags = 0};

        sendmsg(sockfd, &msghdr, MSG_DONTWAIT);
    }

    int sockfd;
    int base_port;
    struct sockaddr_in saddr;
};
