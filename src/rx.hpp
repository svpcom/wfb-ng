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
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <string.h>
#include "fec.h"
#include "wifibroadcast.hpp"
#include <stdexcept>

typedef enum {
    LOCAL,
    FORWARDER,
    AGGREGATOR
} rx_mode_t;

class BaseAggregator
{
public:
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi, const int8_t *noise, uint16_t freq, sockaddr_in *sockaddr) = 0;
    virtual void dump_stats(FILE *fp) = 0;
protected:
    int open_udp_socket_for_tx(const std::string &client_addr, int client_port)
    {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short)client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw std::runtime_error(string_format("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
};


class Forwarder : public BaseAggregator
{
public:
    Forwarder(const std::string &client_addr, int client_port);
    ~Forwarder();
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi, const int8_t *noise, uint16_t freq, sockaddr_in *sockaddr);
    virtual void dump_stats(FILE *) {}
private:
    int sockfd;
};


typedef struct {
    uint64_t block_idx;
    uint8_t** fragments;
    uint8_t *fragment_map;
    uint8_t fragment_to_send_idx;
    uint8_t has_fragments;
} rx_ring_item_t;


#define RX_RING_SIZE 40

static inline int modN(int x, int base)
{
    return (base + (x % base)) % base;
}

class rxAntennaItem
{
public:
    rxAntennaItem(void) : count_all(0),
                          rssi_sum(0), rssi_min(0), rssi_max(0),
                          snr_sum(0), snr_min(0), snr_max(0) {}

    void log_rssi(int8_t rssi, int8_t noise){
        int8_t snr = (noise != SCHAR_MAX) ? rssi - noise : 0;

        if(count_all == 0){
            rssi_min = rssi;
            rssi_max = rssi;
            snr_min = snr;
            snr_max = snr;
        } else {
            rssi_min = std::min(rssi, rssi_min);
            rssi_max = std::max(rssi, rssi_max);
            snr_min = std::min(snr, snr_min);
            snr_max = std::max(snr, snr_max);
        }
        rssi_sum += rssi;
        snr_sum += snr;
        count_all += 1;
    }

    int32_t count_all;
    int32_t rssi_sum;
    int8_t rssi_min;
    int8_t rssi_max;
    int32_t snr_sum;
    int8_t snr_min;
    int8_t snr_max;
};

struct rxAntennaKey
{
    uint16_t freq;
    uint64_t antenna_id;

    bool operator==(const rxAntennaKey &other) const
    {
        return (freq == other.freq && antenna_id == other.antenna_id);
    }
};

template<>
struct std::hash<rxAntennaKey>
{
    std::size_t operator()(const rxAntennaKey& k) const noexcept
    {
        std::size_t h1 = std::hash<uint16_t>{}(k.freq);
        std::size_t h2 = std::hash<uint64_t>{}(k.antenna_id);
        return h1 ^ (h2 << 1); // combine hashes
    }
};

typedef std::unordered_map<rxAntennaKey, rxAntennaItem> rx_antenna_stat_t;

class Aggregator : public BaseAggregator
{
public:
    Aggregator(const std::string &client_addr, int client_port, const std::string &keypair, uint64_t epoch, uint32_t channel_id);
    ~Aggregator();
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi, const int8_t *noise, uint16_t freq, sockaddr_in *sockaddr);
    virtual void dump_stats(FILE *fp);
private:
    void init_fec(int k, int n);
    void deinit_fec(void);
    void send_packet(int ring_idx, int fragment_idx);
    void apply_fec(int ring_idx);
    void log_rssi(const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi, const int8_t *noise, uint16_t freq);
    int get_block_ring_idx(uint64_t block_idx);
    int rx_ring_push(void);
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    int sockfd;
    uint32_t seq;
    rx_ring_item_t rx_ring[RX_RING_SIZE];
    int rx_ring_front; // current packet
    int rx_ring_alloc; // number of allocated entries
    uint64_t last_known_block;  //id of last known block
    uint64_t epoch; // current epoch
    const uint32_t channel_id; // (link_id << 8) + port_number

    // rx->tx keypair
    uint8_t rx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t tx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];

    rx_antenna_stat_t antenna_stat;
    uint32_t count_p_all;
    uint32_t count_p_dec_err;
    uint32_t count_p_dec_ok;
    uint32_t count_p_fec_recovered;
    uint32_t count_p_lost;
    uint32_t count_p_bad;
    uint32_t count_p_override;
    uint32_t count_p_outgoing;
};

class Receiver
{
public:
    Receiver(const char* wlan, int wlan_idx, uint32_t channel_id, BaseAggregator* agg);
    ~Receiver();
    void loop_iter(void);
    int getfd(void){ return fd; }
private:
    int wlan_idx;
    BaseAggregator *agg;
    int fd;
    pcap_t *ppcap;
};
