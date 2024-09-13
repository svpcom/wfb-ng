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
#include <map>
#include <string.h>
#include <stdexcept>

#include "wifibroadcast.hpp"
#include "tx_cmd.h"


// Tags item
typedef struct {
    uint8_t id;
    std::vector<uint8_t> value;
} tags_item_t;


typedef struct {
    std::vector<uint8_t> header;

    // header info
    uint8_t stbc;
    bool ldpc;
    bool short_gi;
    uint8_t bandwidth;
    uint8_t mcs_index;
    bool vht_mode;
    uint8_t vht_nss;
} radiotap_header_t;


radiotap_header_t init_radiotap_header(uint8_t stbc,
                                       bool ldpc,
                                       bool short_gi,
                                       uint8_t bandwidth,
                                       uint8_t mcs_index,
                                       bool vht_mode,
                                       uint8_t vht_nss);

typedef enum {
    LOCAL,
    INJECTOR,
    DISTRIBUTOR
} tx_mode_t;

class Transmitter
{
public:
    Transmitter(int k, int n, const std::string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, std::vector<tags_item_t> &tags);
    virtual ~Transmitter();
    bool send_packet(const uint8_t *buf, size_t size, uint8_t flags);
    void send_session_key(void);
    void init_session(int k, int n);
    void get_fec(int &k, int &n) { k = fec_k; n = fec_n; }
    virtual void select_output(int idx) = 0;
    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes) = 0;
    virtual void update_radiotap_header(radiotap_header_t &radiotap_header) = 0;
    virtual radiotap_header_t get_radiotap_header(void) = 0;
protected:
    virtual void inject_packet(const uint8_t *buf, size_t size) = 0;
    virtual void set_mark(uint32_t idx) = 0;

private:
    Transmitter(const Transmitter&);
    Transmitter& operator=(const Transmitter&);
    void send_block_fragment(size_t packet_size);
    void deinit_session(void);

    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint64_t block_idx; // (block_idx << 8) + fragment_idx = nonce (64bit)
    uint8_t fragment_idx;
    uint8_t** block;
    size_t max_packet_size;
    const uint64_t epoch; // Packets from old epoch will be discarded
    const uint32_t channel_id; // (link_id << 8) + port_number
    const uint32_t fec_delay; // fec packet delay [us]

    // tx->rx keypair
    uint8_t tx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t rx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];
    uint8_t session_packet[MAX_SESSION_PACKET_SIZE];
    uint16_t session_packet_size;
    std::vector<tags_item_t> tags;
};


class txAntennaItem
{
public:
    txAntennaItem(void) : count_p_injected(0), count_b_injected(0), count_p_dropped(0), latency_sum(0), latency_min(0), latency_max(0) {}

    void log_latency(uint64_t latency, bool succeeded, uint32_t packet_size) {
        if(count_p_injected + count_p_dropped == 0)
        {
            latency_min = latency;
            latency_max = latency;
        }
        else
        {
            latency_min = std::min(latency, latency_min);
            latency_max = std::max(latency, latency_max);
        }

        latency_sum += latency;

        if (succeeded)
        {
            count_p_injected += 1;
            count_b_injected += packet_size;
        }
        else
        {
            count_p_dropped += 1;
        }
    }

    uint32_t count_p_injected;
    uint32_t count_b_injected;
    uint32_t count_p_dropped;
    uint64_t latency_sum;
    uint64_t latency_min;
    uint64_t latency_max;
};

typedef std::unordered_map<uint64_t, txAntennaItem> tx_antenna_stat_t;

class RawSocketTransmitter : public Transmitter
{
public:
    RawSocketTransmitter(int k, int n, const std::string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, std::vector<tags_item_t> &tags,
                         const std::vector<std::string> &wlans, radiotap_header_t &radiotap_header,
                         uint8_t frame_type, bool use_qdisc, uint32_t fwmark_base);
    virtual ~RawSocketTransmitter();

    virtual void select_output(int idx)
    {
        current_output = idx;
    }

    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes);
    virtual void update_radiotap_header(radiotap_header_t &radiotap_header)
    {
        this->radiotap_header = radiotap_header;
    }

    virtual radiotap_header_t get_radiotap_header(void)
    {
        return radiotap_header;
    }

private:
    virtual void inject_packet(const uint8_t *buf, size_t size);

    virtual void set_mark(uint32_t idx)
    {
        fwmark = fwmark_base + idx;
    }

    const uint32_t channel_id;
    int current_output;
    uint16_t ieee80211_seq;
    std::vector<int> sockfds;
    std::map<int, uint32_t> fd_fwmarks;
    tx_antenna_stat_t antenna_stat;
    radiotap_header_t radiotap_header;
    const uint8_t frame_type;
    const bool use_qdisc;
    const uint32_t fwmark_base;
    uint32_t fwmark;
};


class UdpTransmitter : public Transmitter
{
public:
    UdpTransmitter(int k, int n, const std::string &keypair, const std::string &client_addr, int base_port, uint64_t epoch, uint32_t channel_id,
                   uint32_t fec_delay, std::vector<tags_item_t> &tags, bool use_qdisc, uint32_t fwmark_base): \
        Transmitter(k, n, keypair, epoch, channel_id, fec_delay, tags), radiotap_header({}), base_port(base_port), use_qdisc(use_qdisc), fwmark_base(fwmark_base)
    {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        memset(&saddr, '\0', sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short)base_port);
    }

    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes) {}

    virtual ~UdpTransmitter()
    {
        close(sockfd);
    }

    virtual void select_output(int idx)
    {
        assert(idx >= 0);
        saddr.sin_port = htons((unsigned short)(base_port + idx));
    }

    virtual void set_mark(uint32_t idx)
    {
        if (!use_qdisc)
        {
            return;
        }

        uint32_t sockopt = this->fwmark_base + idx;
        if(setsockopt(sockfd, SOL_SOCKET, SO_MARK, (const void *)&sockopt , sizeof(sockopt)) !=0)
        {
            throw runtime_error(string_format("Unable to set SO_MARK fd(%d)=%u: %s", sockfd, sockopt, strerror(errno)));
        }
    }

    virtual void update_radiotap_header(radiotap_header_t &radiotap_header)
    {
        this->radiotap_header = radiotap_header;
    }

    virtual radiotap_header_t get_radiotap_header(void)
    {
        return radiotap_header;
    }


private:
    virtual void inject_packet(const uint8_t *buf, size_t size)
    {
        assert(size <= MAX_FORWARDER_PACKET_SIZE);
        wrxfwd_t fwd_hdr = { .wlan_idx = (uint8_t)(rand() % 2) };

        memset(fwd_hdr.antenna, 0xff, sizeof(fwd_hdr.antenna));
        memset(fwd_hdr.rssi, SCHAR_MIN, sizeof(fwd_hdr.rssi));
        memset(fwd_hdr.noise, SCHAR_MAX, sizeof(fwd_hdr.noise));

        fwd_hdr.mcs_index = 1;
        fwd_hdr.bandwidth = 20;
        fwd_hdr.freq = htons(4321);
        fwd_hdr.antenna[0] = (uint8_t)(rand() % 2);
        fwd_hdr.rssi[0] = -42;
        fwd_hdr.noise[0] = -70;

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

    radiotap_header_t radiotap_header;
    int sockfd;
    int base_port;
    struct sockaddr_in saddr;
    const bool use_qdisc;
    const uint32_t fwmark_base;
};


class RemoteTransmitter : public Transmitter
{
public:
    RemoteTransmitter(int k, int n, const std::string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, std::vector<tags_item_t> &tags,
                      const std::vector<std::pair<std::string, std::vector<uint16_t>>> &remote_hosts, radiotap_header_t &radiotap_header,
                      uint8_t frame_type, bool use_qdisc, uint32_t fwmark_base);
    virtual ~RemoteTransmitter()
    {
        close(sockfd);
    }

    virtual void select_output(int idx)
    {
        current_output = idx;
    }

    virtual void dump_stats(FILE *fp, uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes);
    virtual void update_radiotap_header(radiotap_header_t &radiotap_header)
    {
        this->radiotap_header = radiotap_header;
    }

    virtual radiotap_header_t get_radiotap_header(void)
    {
        return radiotap_header;
    }

private:
    virtual void inject_packet(const uint8_t *buf, size_t size);

    virtual void set_mark(uint32_t idx)
    {
        fwmark = fwmark_base + idx;
    }

    const uint32_t channel_id;
    int current_output;
    uint16_t ieee80211_seq;
    int sockfd;
    std::vector<struct sockaddr_in> sockaddrs;
    std::map<int, uint64_t> output_to_ant_id;
    tx_antenna_stat_t antenna_stat;
    radiotap_header_t radiotap_header;
    const uint8_t frame_type;
    const bool use_qdisc;
    const uint32_t fwmark_base;
    uint32_t fwmark;
};


class RawSocketInjector
{
public:

    RawSocketInjector(const vector<string> &wlans, bool use_qdisc) : use_qdisc(use_qdisc)
    {
        for(auto it=wlans.begin(); it!=wlans.end(); it++)
        {
            int fd = socket(PF_PACKET, SOCK_RAW, 0);
            if (fd < 0)
            {
                throw runtime_error(string_format("Unable to open PF_PACKET socket: %s", strerror(errno)));
            }

            if(!use_qdisc)
            {
                const int optval = 1;
                if(setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, (const void *)&optval , sizeof(optval)) !=0)
                {
                    close(fd);
                    throw runtime_error(string_format("Unable to set PACKET_QDISC_BYPASS: %s", strerror(errno)));
                }
            }

            struct ifreq ifr;
            memset(&ifr, '\0', sizeof(ifr));
            strncpy(ifr.ifr_name, it->c_str(), sizeof(ifr.ifr_name) - 1);

            if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
            {
                close(fd);
                throw runtime_error(string_format("Unable to get interface index for %s: %s", it->c_str(), strerror(errno)));
            }

            struct sockaddr_ll sll;
            memset(&sll, '\0', sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = ifr.ifr_ifindex;
            sll.sll_protocol = 0;

            if (::bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
            {
                close(fd);
                throw runtime_error(string_format("Unable to bind to %s: %s", it->c_str(), strerror(errno)));
            }

            sockfds.push_back(fd);
            fd_fwmarks[fd] = 0;
        }
    }

    void inject_packet(int wlan_idx, const uint8_t *buf, size_t size, uint32_t fwmark)
    {
        int fd = sockfds[wlan_idx];

        if (use_qdisc && fd_fwmarks[fd] != fwmark)
        {
            uint32_t sockopt = fwmark;

            if(setsockopt(fd, SOL_SOCKET, SO_MARK, (const void *)&sockopt , sizeof(sockopt)) !=0)
            {
                throw runtime_error(string_format("Unable to set SO_MARK fd(%d)=%u: %s", fd, sockopt, strerror(errno)));
            }

            fd_fwmarks[fd] = fwmark;
        }

        if (send(fd, buf, size, 0) < 0 && errno != ENOBUFS)
        {
            throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
        }
    }

    ~RawSocketInjector()
    {
        for(auto it=sockfds.begin(); it != sockfds.end(); it++)
        {
            close(*it);
        }
    }

private:
    std::vector<int> sockfds;
    std::map<int, uint32_t> fd_fwmarks;
    const bool use_qdisc;
};
