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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/resource.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/random.h>
#include <inttypes.h>

#include <string>
#include <memory>
#include <vector>
#include <set>

extern "C"
{
#include "fec.h"
}

using namespace std;

#include "wifibroadcast.hpp"
#include "tx.hpp"

Transmitter::Transmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, vector<tags_item_t> &tags) : \
    fec_p(NULL), fec_k(-1), fec_n(-1),
    block_idx(0), fragment_idx(0),
    max_packet_size(0),
    epoch(epoch),
    channel_id(channel_id),
    fec_delay(fec_delay),
    tx_secretkey{},
    rx_publickey{},
    session_key{},
    session_packet{},
    session_packet_size(0),
    tags(tags)
{

    FILE *fp;
    if ((fp = fopen(keypair.c_str(), "r")) == NULL)
    {
        throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
    }
    if (fread(tx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read tx secret key: %s", strerror(errno)));
    }
    if (fread(rx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read rx public key: %s", strerror(errno)));
    }
    fclose(fp);

    init_session(k, n);
}

Transmitter::~Transmitter()
{
    if (fec_p != NULL)
    {
        deinit_session();
    }
}


void Transmitter::deinit_session(void)
{
    for(int i=0; i < fec_n; i++)
    {
        delete[] block[i];
    }

    delete[] block;
    fec_free(fec_p);

    block = NULL;
    fec_p = NULL;
    fec_k = -1;
    fec_n = -1;
}

void Transmitter::init_session(int k, int n)
{
    if (fec_p != NULL)
    {
        deinit_session();
    }

    assert(fec_p == NULL);
    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    fec_k = k;
    fec_n = n;
    fec_p = fec_new(fec_k, fec_n);

    block = new uint8_t*[fec_n];
    for(int i=0; i < fec_n; i++)
    {
        block[i] = new uint8_t[MAX_FEC_PAYLOAD];
    }

    block_idx = 0;
    fragment_idx = 0;

    // init session key
    randombytes_buf(session_key, sizeof(session_key));

    // fill packet header
    wsession_hdr_t *session_hdr = (wsession_hdr_t *)session_packet;
    session_hdr->packet_type = WFB_PACKET_SESSION;

    randombytes_buf(session_hdr->session_nonce, sizeof(session_hdr->session_nonce));

    // fill packet contents

    uint8_t tmp[MAX_SESSION_PACKET_SIZE - crypto_box_MACBYTES - sizeof(wsession_hdr_t)];

    // Fill fixed headers
    {
        wsession_data_t* session_data = (wsession_data_t*)tmp;
        assert(sizeof(*session_data) <= sizeof(tmp));

        session_data->epoch = htobe64(epoch);
        session_data->channel_id = htobe32(channel_id);
        session_data->fec_type = WFB_FEC_VDM_RS;
        session_data->k = (uint8_t)fec_k;
        session_data->n = (uint8_t)fec_n;

        assert(sizeof(session_data->session_key) == sizeof(session_key));
        memcpy(session_data->session_key, session_key, sizeof(session_key));
    }

    // Fill optional Tags

    uint32_t session_data_size = sizeof(wsession_data_t);
    for(auto it = tags.begin(); it != tags.end(); it++)
    {
        tlv_hdr_t* tlv = (tlv_hdr_t*)((uint8_t*)tmp + session_data_size);
        session_data_size += sizeof(tlv_hdr_t) + it->value.size();
        assert(session_data_size <= sizeof(tmp));

        tlv->id = it->id;
        tlv->len = it->value.size();
        memcpy(tlv->value, &it->value[0], it->value.size());
    }

    if (crypto_box_easy(session_packet + sizeof(wsession_hdr_t),
                        (uint8_t*)tmp, session_data_size,
                        session_hdr->session_nonce, rx_publickey, tx_secretkey) != 0)
    {
        throw runtime_error("Unable to make session key!");
    }

    session_packet_size = sizeof(wsession_hdr_t) + session_data_size + crypto_box_MACBYTES;
    assert(session_packet_size <= MAX_SESSION_PACKET_SIZE);
}


RawSocketTransmitter::RawSocketTransmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay,
                                           vector<tags_item_t> &tags, const vector<string> &wlans, radiotap_header_t &radiotap_header,
                                           uint8_t frame_type, bool use_qdisc, uint32_t fwmark_base) : \
    Transmitter(k, n, keypair, epoch, channel_id, fec_delay, tags),
    channel_id(channel_id),
    current_output(0),
    ieee80211_seq(0),
    radiotap_header(radiotap_header),
    frame_type(frame_type),
    use_qdisc(use_qdisc),
    fwmark_base(fwmark_base),
    fwmark(fwmark_base)
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

void RawSocketTransmitter::inject_packet(const uint8_t *buf, size_t size)
{
    assert(size <= MAX_FORWARDER_PACKET_SIZE);
    uint8_t ieee_hdr[sizeof(ieee80211_header)];

    // fill default values
    memcpy(ieee_hdr, ieee80211_header, sizeof(ieee80211_header));

    // frame_type
    ieee_hdr[0] = frame_type;

    // channel_id
    uint32_t channel_id_be = htobe32(channel_id);
    memcpy(ieee_hdr + SRC_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));
    memcpy(ieee_hdr + DST_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));

    // sequence number
    ieee_hdr[FRAME_SEQ_LB] = ieee80211_seq & 0xff;
    ieee_hdr[FRAME_SEQ_HB] = (ieee80211_seq >> 8) & 0xff;
    ieee80211_seq += 16;

    struct iovec iov[3] = \
        {
            // radiotap header
            { .iov_base = (void*)&radiotap_header.header[0],
              .iov_len = radiotap_header.header.size()
            },
            // ieee80211 header
            { .iov_base = (void*)ieee_hdr,
              .iov_len = sizeof(ieee_hdr)
            },
            // packet payload
            { .iov_base = (void*)buf,
              .iov_len = size
            }
        };

    struct msghdr msghdr = \
        { .msg_name = NULL,
          .msg_namelen = 0,
          .msg_iov = iov,
          .msg_iovlen = 3,
          .msg_control = NULL,
          .msg_controllen = 0,
          .msg_flags = 0};

    if (current_output >= 0)
    {
        // Normal mode - only one card do packet transmission in a time
        uint64_t start_us = get_time_us();
        int fd = sockfds[current_output];

        if (use_qdisc && fd_fwmarks[fd] != fwmark)
        {
            uint32_t sockopt = fwmark;

            if(setsockopt(fd, SOL_SOCKET, SO_MARK, (const void *)&sockopt , sizeof(sockopt)) !=0)
            {
                throw runtime_error(string_format("Unable to set SO_MARK fd(%d)=%u: %s", fd, sockopt, strerror(errno)));
            }

            fd_fwmarks[fd] = fwmark;
        }

        int rc = sendmsg(fd, &msghdr, 0);

        if (rc < 0 && errno != ENOBUFS)
        {
            throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
        }

        uint64_t key = (uint64_t)(current_output) << 8 | (uint64_t)0xff;
        antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
    }
    else
    {
        // Mirror mode - transmit packet via all cards
        // Use only for different frequency channels
        int i = 0;
        for(auto it=sockfds.begin(); it != sockfds.end(); it++, i++)
        {
            uint64_t start_us = get_time_us();
            int fd = *it;

            if (use_qdisc && fd_fwmarks[fd] != fwmark)
            {
                uint32_t sockopt = fwmark;

                if(setsockopt(fd, SOL_SOCKET, SO_MARK, (const void *)&sockopt , sizeof(sockopt)) !=0)
                {
                    throw runtime_error(string_format("Unable to set SO_MARK fd(%d)=%u: %s", fd, sockopt, strerror(errno)));
                }

                fd_fwmarks[fd] = fwmark;
            }

            int rc = sendmsg(fd, &msghdr, 0);

            if (rc < 0 && errno != ENOBUFS)
            {
                throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
            }

            uint64_t key = (uint64_t)(i) << 8 | (uint64_t)0xff;
            antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
        }
    }

}

void RawSocketTransmitter::dump_stats(FILE *fp, uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes)
{
    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        fprintf(fp, "%" PRIu64 "\tTX_ANT\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                ts, it->first,
                it->second.count_p_injected, it->second.count_p_dropped,
                it->second.latency_min,
                it->second.latency_sum / (it->second.count_p_injected + it->second.count_p_dropped),
                it->second.latency_max);

        injected_packets += it->second.count_p_injected;
        dropped_packets += it->second.count_p_dropped;
        injected_bytes += it->second.count_b_injected;
    }
    antenna_stat.clear();
}

RawSocketTransmitter::~RawSocketTransmitter()
{
    for(auto it=sockfds.begin(); it != sockfds.end(); it++)
    {
        close(*it);
    }
}


RemoteTransmitter::RemoteTransmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay,
                                     vector<tags_item_t> &tags, const vector<pair<string, vector<uint16_t>>> &remote_hosts, radiotap_header_t &radiotap_header,
                                     uint8_t frame_type, bool use_qdisc, uint32_t fwmark_base) : \
    Transmitter(k, n, keypair, epoch, channel_id, fec_delay, tags),
    channel_id(channel_id),
    current_output(0),
    ieee80211_seq(0),
    radiotap_header(radiotap_header),
    frame_type(frame_type),
    use_qdisc(use_qdisc),
    fwmark_base(fwmark_base),
    fwmark(fwmark_base)
{

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    int output = 0;
    for(auto h_it=remote_hosts.begin(); h_it!=remote_hosts.end(); h_it++)
    {
        uint8_t wlan_id = 0;
        for(auto p_it=h_it->second.begin(); p_it != h_it->second.end(); p_it++, output++, wlan_id++)
        {
            struct sockaddr_in saddr;
            memset(&saddr, '\0', sizeof(saddr));
            saddr.sin_family = AF_INET;
            saddr.sin_addr.s_addr = inet_addr(h_it->first.c_str());
            saddr.sin_port = htons((unsigned short)*p_it);
            sockaddrs.push_back(saddr);
            output_to_ant_id[output] = ((uint64_t)ntohl(saddr.sin_addr.s_addr) << 32) | (uint64_t)(wlan_id) << 8 | (uint64_t)0xff;
        }
    }
}

void RemoteTransmitter::inject_packet(const uint8_t *buf, size_t size)
{
    assert(size <= MAX_FORWARDER_PACKET_SIZE);
    uint8_t ieee_hdr[sizeof(ieee80211_header)];

    // fill default values
    memcpy(ieee_hdr, ieee80211_header, sizeof(ieee80211_header));

    // frame_type
    ieee_hdr[0] = frame_type;

    // channel_id
    uint32_t channel_id_be = htobe32(channel_id);
    memcpy(ieee_hdr + SRC_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));
    memcpy(ieee_hdr + DST_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));

    // sequence number
    ieee_hdr[FRAME_SEQ_LB] = ieee80211_seq & 0xff;
    ieee_hdr[FRAME_SEQ_HB] = (ieee80211_seq >> 8) & 0xff;
    ieee80211_seq += 16;

    uint32_t _fwmark = use_qdisc ? htonl(this->fwmark) : 0;

    struct iovec iov[4] = \
        {
            // fwmark
            {
                .iov_base = (void*)&_fwmark,
                .iov_len = sizeof(_fwmark),
            },
            // radiotap header
            { .iov_base = (void*)&radiotap_header.header[0],
              .iov_len = radiotap_header.header.size()
            },
            // ieee80211 header
            { .iov_base = (void*)ieee_hdr,
              .iov_len = sizeof(ieee_hdr)
            },
            // packet payload
            { .iov_base = (void*)buf,
              .iov_len = size
            }
        };

    struct msghdr msghdr = \
        { .msg_name = NULL,
          .msg_namelen = 0,
          .msg_iov = iov,
          .msg_iovlen = 4,
          .msg_control = NULL,
          .msg_controllen = 0,
          .msg_flags = 0};

    struct sockaddr_in saddr;

    if (current_output >= 0)
    {
        // Normal mode - only one card do packet transmission in a time
        uint64_t start_us = get_time_us();

        saddr = sockaddrs[current_output];
        msghdr.msg_name = &saddr;
        msghdr.msg_namelen = sizeof(saddr);

        int rc = sendmsg(sockfd, &msghdr, 0);

        if (rc < 0 && errno != ENOBUFS)
        {
            throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
        }

        uint64_t key = output_to_ant_id[current_output];
        antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
    }
    else
    {
        // Mirror mode - transmit packet via all cards
        // Use only for different frequency channels
        int i = 0;
        for(auto it=sockaddrs.begin(); it != sockaddrs.end(); it++, i++)
        {
            uint64_t start_us = get_time_us();

            saddr = *it;
            msghdr.msg_name = &saddr;
            msghdr.msg_namelen = sizeof(saddr);

            int rc = sendmsg(sockfd, &msghdr, 0);

            if (rc < 0 && errno != ENOBUFS)
            {
                throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
            }

            uint64_t key = output_to_ant_id[i];
            antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
        }
    }

}

void RemoteTransmitter::dump_stats(FILE *fp, uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes)
{
    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        fprintf(fp, "%" PRIu64 "\tTX_ANT\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                ts, it->first,
                it->second.count_p_injected, it->second.count_p_dropped,
                it->second.latency_min,
                it->second.latency_sum / (it->second.count_p_injected + it->second.count_p_dropped),
                it->second.latency_max);

        injected_packets += it->second.count_p_injected;
        dropped_packets += it->second.count_p_dropped;
        injected_bytes += it->second.count_b_injected;
    }
    antenna_stat.clear();
}



void Transmitter::send_block_fragment(size_t packet_size)
{
    uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
    long long unsigned int ciphertext_len;

    assert(packet_size <= MAX_FEC_PAYLOAD);

    block_hdr->packet_type = WFB_PACKET_DATA;
    block_hdr->data_nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);

    // encrypted payload
    if (crypto_aead_chacha20poly1305_encrypt(ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                                             block[fragment_idx], packet_size,
                                             (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                                             NULL, (uint8_t*)(&(block_hdr->data_nonce)), session_key) < 0)
    {
        throw runtime_error("Unable to encrypt packet!");
    }

    inject_packet(ciphertext, sizeof(wblock_hdr_t) + ciphertext_len);
}

void Transmitter::send_session_key(void)
{
    //fprintf(stderr, "Announce session key\n");
    inject_packet((uint8_t*)session_packet, session_packet_size);
}

bool Transmitter::send_packet(const uint8_t *buf, size_t size, uint8_t flags)
{
    assert(size <= MAX_PAYLOAD_SIZE);

    // FEC-only packets are only for closing already opened blocks
    if (fragment_idx == 0 && (flags & WFB_PACKET_FEC_ONLY))
    {
        return false;
    }

    wpacket_hdr_t *packet_hdr = (wpacket_hdr_t*)block[fragment_idx];

    packet_hdr->flags = flags;
    packet_hdr->packet_size = htobe16(size);

    if(size > 0)
    {
        assert(buf != NULL);
        memcpy(block[fragment_idx] + sizeof(wpacket_hdr_t), buf, size);
    }

    memset(block[fragment_idx] + sizeof(wpacket_hdr_t) + size, '\0', MAX_FEC_PAYLOAD - (sizeof(wpacket_hdr_t) + size));

    // mark data packets with fwmark
    if(fragment_idx == 0)
    {
        set_mark(0);
    }

    send_block_fragment(sizeof(wpacket_hdr_t) + size);
    max_packet_size = max(max_packet_size, sizeof(wpacket_hdr_t) + size);
    fragment_idx += 1;

    if (fragment_idx < fec_k)  return true;

    fec_encode(fec_p, (const uint8_t**)block, block + fec_k, max_packet_size);

    // mark fec packets with fwmark + 1
    set_mark(1);

    while (fragment_idx < fec_n)
    {
        if(fec_delay > 0)
        {
            struct timespec t = { .tv_sec = (time_t)(fec_delay / 1000000),
                                  .tv_nsec = (suseconds_t)(fec_delay % 1000000) * 1000 };

            int rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL);

            if(rc != 0 && rc != EINTR)
            {
                throw runtime_error(string_format("clock_nanosleep: %s", strerror(rc)));
            }
        }

        send_block_fragment(max_packet_size);
        fragment_idx += 1;
    }
    block_idx += 1;
    fragment_idx = 0;
    max_packet_size = 0;

    // Generate new session key after MAX_BLOCK_IDX blocks
    if (block_idx > MAX_BLOCK_IDX)
    {
        init_session(fec_k, fec_n);
        for(int i = 0; i < fec_n - fec_k + 1; i++)
        {
            send_session_key();
        }
    }

    return true;
}

// Extract SO_RXQ_OVFL counter
uint32_t extract_rxq_overflow(struct msghdr *msg)
{
    struct cmsghdr *cmsg;
    uint32_t rtn;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
            memcpy(&rtn, CMSG_DATA(cmsg), sizeof(rtn));
            return rtn;
        }
    }
    return 0;
}

void data_source(unique_ptr<Transmitter> &t, vector<int> &rx_fd, int control_fd, int fec_timeout, bool mirror, int log_interval)
{
    int nfds = rx_fd.size();
    assert(nfds > 0);

    struct pollfd fds[nfds + 1];
    memset(fds, '\0', sizeof(fds));

    for(size_t i=0; i < rx_fd.size(); i++)
    {
        fds[i].fd = rx_fd[i];
        fds[i].events = POLLIN;
    }

    fds[nfds].fd = control_fd;
    fds[nfds].events = POLLIN;

    uint64_t session_key_announce_ts = get_time_ms();
    uint32_t rxq_overflow = 0;
    uint64_t log_send_ts = get_time_ms();
    uint64_t fec_close_ts = fec_timeout > 0 ? get_time_ms() + fec_timeout : 0;
    uint32_t count_p_fec_timeouts = 0; // empty packets sent to close fec block due to timeout
    uint32_t count_p_incoming = 0;   // incoming udp packets (received + dropped due to rxq overflow)
    uint32_t count_b_incoming = 0;   // incoming udp bytes (received only)
    uint32_t count_p_injected = 0;  // successfully injected packets (include additional fec packets)
    uint32_t count_b_injected = 0;  // successfully injected bytes (include additional fec packets)
    uint32_t count_p_dropped = 0;   // dropped due to rxq overflows or injection timeout
    uint32_t count_p_truncated = 0; // injected large packets that were truncated
    int start_fd_idx = 0;

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int poll_timeout = log_send_ts > cur_ts ? log_send_ts - cur_ts : 0;

        if (fec_timeout > 0)
        {
            poll_timeout = std::min(poll_timeout, (int)(fec_close_ts > cur_ts ? fec_close_ts - cur_ts : 0));
        }

        int rc = poll(fds, nfds + 1, poll_timeout);

        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();

        if (cur_ts >= log_send_ts)  // log timeout expired
        {
            t->dump_stats(stdout, cur_ts, count_p_injected, count_p_dropped, count_b_injected);

            fprintf(stdout, "%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u:%u\n",
                    cur_ts, count_p_fec_timeouts, count_p_incoming, count_b_incoming, count_p_injected, count_b_injected, count_p_dropped, count_p_truncated);
            fflush(stdout);

            if(count_p_dropped)
            {
                fprintf(stderr, "%u packets dropped\n", count_p_dropped);
            }

            if(count_p_truncated)
            {
                fprintf(stderr, "%u packets truncated\n", count_p_truncated);
            }

            count_p_fec_timeouts = 0;
            count_p_incoming = 0;
            count_b_incoming = 0;
            count_p_injected = 0;
            count_b_injected = 0;
            count_p_dropped = 0;
            count_p_truncated = 0;

            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        // Check control socket first
        if (rc > 0 && fds[nfds].revents & (POLLERR | POLLNVAL))
        {
            throw runtime_error(string_format("socket error: %s", strerror(errno)));
        }

        if (rc > 0 && fds[nfds].revents & POLLIN)
        {
            rc -= 1;
            int fd = fds[nfds].fd;

            for(;;)
            {
                cmd_req_t req = {};
                cmd_resp_t resp = {};
                ssize_t rsize;
                struct sockaddr_in from_addr;
                socklen_t addr_size = sizeof(from_addr);

                if ((rsize = recvfrom(fd, &req, sizeof(req), MSG_DONTWAIT, (sockaddr*)&from_addr, &addr_size )) < 0 || addr_size > sizeof(from_addr))
                {
                    if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
                    break;
                }

                if(rsize < (ssize_t)offsetof(cmd_req_t, u)) continue;

                resp.req_id = req.req_id;
                resp.rc = 0;

                switch(req.cmd_id)
                {
                case CMD_SET_FEC:
                {
                    if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_fec))
                    {
                        resp.rc = htonl(EINVAL);
                        sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                        continue;
                    }

                    int fec_k = req.u.cmd_set_fec.k;
                    int fec_n = req.u.cmd_set_fec.n;

                    if(!(fec_k <= fec_n && fec_k >=1 && fec_n >= 1 && fec_n < 256))
                    {
                        resp.rc = htonl(EINVAL);
                        sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                        fprintf(stderr, "Rejecting new FEC settings");
                        continue;
                    }

                    // Close open FEC block if any
                    while(t->send_packet(NULL, 0, WFB_PACKET_FEC_ONLY));

                    t->init_session(fec_k, fec_n);

                    // Emulate FEC for initial session key distribution
                    for(int i = 0; i < fec_n - fec_k + 1; i++)
                    {
                        t->send_session_key();
                    }

                    sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                    fprintf(stderr, "Session restarted with FEC %d/%d\n", fec_k, fec_n);
                }
                break;

                case CMD_SET_RADIO:
                {
                    if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_radio))
                    {
                        resp.rc = htonl(EINVAL);
                        sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                        continue;
                    }

                    try
                    {
                        auto radiotap_header = init_radiotap_header(req.u.cmd_set_radio.stbc,
                                                                    req.u.cmd_set_radio.ldpc,
                                                                    req.u.cmd_set_radio.short_gi,
                                                                    req.u.cmd_set_radio.bandwidth,
                                                                    req.u.cmd_set_radio.mcs_index,
                                                                    req.u.cmd_set_radio.vht_mode,
                                                                    req.u.cmd_set_radio.vht_nss);
                        t->update_radiotap_header(radiotap_header);
                    }
                    catch(runtime_error &e)
                    {
                        resp.rc = htonl(EINVAL);
                        sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                        fprintf(stderr, "Rejecting new radiotap header: %s\n", e.what());
                        continue;
                    }

                    sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                    fprintf(stderr,
                            "Radiotap updated with stbc=%d, ldpc=%d, short_gi=%d, bandwidth=%d, mcs_index=%d, vht_mode=%d, vht_nss=%d\n",
                            req.u.cmd_set_radio.stbc,
                            req.u.cmd_set_radio.ldpc,
                            req.u.cmd_set_radio.short_gi,
                            req.u.cmd_set_radio.bandwidth,
                            req.u.cmd_set_radio.mcs_index,
                            req.u.cmd_set_radio.vht_mode,
                            req.u.cmd_set_radio.vht_nss);
                }
                break;

                case CMD_GET_FEC:
                {
                    int fec_k = 0, fec_n = 0;

                    if (rsize != offsetof(cmd_req_t, u))
                    {
                        resp.rc = htonl(EINVAL);
                        sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                        continue;
                    }

                    t->get_fec(fec_k, fec_n);

                    resp.u.cmd_get_fec.k = fec_k;
                    resp.u.cmd_get_fec.n = fec_n;

                    sendto(fd, &resp, offsetof(cmd_resp_t, u) + sizeof(resp.u.cmd_get_fec), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                }
                break;

                case CMD_GET_RADIO:
                {
                    if (rsize != offsetof(cmd_req_t, u))
                    {
                        resp.rc = htonl(EINVAL);
                        sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                        continue;
                    }

                    radiotap_header_t hdr = t->get_radiotap_header();

                    resp.u.cmd_get_radio.stbc = hdr.stbc;
                    resp.u.cmd_get_radio.ldpc = hdr.ldpc;
                    resp.u.cmd_get_radio.short_gi = hdr.short_gi;
                    resp.u.cmd_get_radio.bandwidth = hdr.bandwidth;
                    resp.u.cmd_get_radio.mcs_index = hdr.mcs_index;
                    resp.u.cmd_get_radio.vht_mode = hdr.vht_mode;
                    resp.u.cmd_get_radio.vht_nss = hdr.vht_nss;

                    sendto(fd, &resp, offsetof(cmd_resp_t, u) + sizeof(resp.u.cmd_get_radio), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                }
                break;

                default:
                {
                    resp.rc = htonl(ENOTSUP);
                    sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                    continue;
                }
                break;
                }
            }
        }

        if (rc == 0) // poll timeout
        {
            // close fec only if no data packets and fec timeout expired
            if (fec_timeout > 0 && cur_ts >= fec_close_ts)
            {
                if(t->send_packet(NULL, 0, WFB_PACKET_FEC_ONLY))
                {
                    count_p_fec_timeouts += 1;
                }
                fec_close_ts = cur_ts + fec_timeout;
            }
            continue;
        }

        // rc > 0: events detected
        // start from last fd index and reset it to zero
        int _tmp = start_fd_idx;
        start_fd_idx = 0;

        for(int i = _tmp; rc > 0; i = (i + 1) % nfds)
        {
            assert(i < nfds);

            if (fds[i].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (fds[i].revents & POLLIN)
            {
                uint8_t buf[MAX_PAYLOAD_SIZE + 1];
                uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];
                rc -= 1;

                t->select_output(mirror ? -1 : (i));

                for(;;)
                {
                    ssize_t rsize;
                    int fd = fds[i].fd;
                    struct iovec iov = { .iov_base = (void*)buf,
                                         .iov_len = sizeof(buf) };

                    struct msghdr msghdr = { .msg_name = NULL,
                                             .msg_namelen = 0,
                                             .msg_iov = &iov,
                                             .msg_iovlen = 1,
                                             .msg_control = &cmsgbuf,
                                             .msg_controllen = sizeof(cmsgbuf),
                                             .msg_flags = 0 };

                    memset(cmsgbuf, '\0', sizeof(cmsgbuf));

                    if ((rsize = recvmsg(fd, &msghdr, MSG_DONTWAIT)) < 0)
                    {
                        if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
                        break;
                    }

                    count_p_incoming += 1;
                    count_b_incoming += rsize;

                    if (rsize > (ssize_t)MAX_PAYLOAD_SIZE)
                    {
                        rsize = MAX_PAYLOAD_SIZE;
                        count_p_truncated += 1;
                    }

                    uint32_t cur_rxq_overflow = extract_rxq_overflow(&msghdr);
                    if (cur_rxq_overflow != rxq_overflow)
                    {
                        // Count dropped packets as possible incoming
                        count_p_dropped += (cur_rxq_overflow - rxq_overflow);
                        count_p_incoming += (cur_rxq_overflow - rxq_overflow);
                        rxq_overflow = cur_rxq_overflow;
                    }

                    cur_ts = get_time_ms();

                    if (cur_ts >= session_key_announce_ts)
                    {
                        // Announce session key
                        t->send_session_key();

                        // Session packet interval is not in fixed grid because
                        // we yield session packets only if there are data packets
                        session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_MSEC;
                    }

                    t->send_packet(buf, rsize, 0);

                    if (cur_ts >= log_send_ts)  // log timeout expired
                    {
                        // Save current index and go to outer loop
                        // We need to transmit all packets from the queue before tx card switch
                        start_fd_idx = i;
                        rc = 0;
                        break;
                    }
                }
            }
        }

        // reset fec timeout if data arrived
        if(fec_timeout > 0)
        {
            fec_close_ts = get_time_ms() + fec_timeout;
        }
    }
}


radiotap_header_t init_radiotap_header(uint8_t stbc,
                                       bool ldpc,
                                       bool short_gi,
                                       uint8_t bandwidth,
                                       uint8_t mcs_index,
                                       bool vht_mode,
                                       uint8_t vht_nss)
{
    radiotap_header_t res = {
        .header = {},
        .stbc = stbc,
        .ldpc = ldpc,
        .short_gi = short_gi,
        .bandwidth = bandwidth,
        .mcs_index = mcs_index,
        .vht_mode = vht_mode,
        .vht_nss = vht_nss,
    };

    if (!vht_mode)
    {
        // Set flags in HT radiotap header
        uint8_t flags = 0;

        switch(bandwidth)
        {
        case 10:
        case 20:
            flags |= IEEE80211_RADIOTAP_MCS_BW_20;
            break;
        case 40:
            flags |= IEEE80211_RADIOTAP_MCS_BW_40;
            break;
        default:
            throw runtime_error(string_format("Unsupported HT bandwidth: %d", bandwidth));
        }

        if (short_gi)
        {
            flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }

        switch(stbc)
        {
        case 0:
            break;
        case 1:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        case 2:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_2 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        case 3:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_3 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        default:
            throw runtime_error(string_format("Unsupported HT STBC type: %d", stbc));
        }

        if (ldpc)
        {
            flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
        }

        copy(radiotap_header_ht, radiotap_header_ht + sizeof(radiotap_header_ht), back_inserter(res.header));

        res.header[MCS_FLAGS_OFF] = flags;
        res.header[MCS_IDX_OFF] = mcs_index;
    }
    else
    {
        // Set flags in VHT radiotap header
        uint8_t flags = 0;

        copy(radiotap_header_vht, radiotap_header_vht + sizeof(radiotap_header_vht), back_inserter(res.header));

        if (short_gi)
        {
            flags |= IEEE80211_RADIOTAP_VHT_FLAG_SGI;
        }

        if (stbc)
        {
            flags |= IEEE80211_RADIOTAP_VHT_FLAG_STBC;
        }

        switch(bandwidth)
        {
        case 10:
        case 20:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_20M;
            break;
        case 40:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_40M;
            break;
        case 80:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_80M;
            break;
        case 160:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_160M;
            break;
        default:
            throw runtime_error(string_format("Unsupported VHT bandwidth: %d", bandwidth));
        }

        if (ldpc)
        {
            res.header[VHT_CODING_OFF] = IEEE80211_RADIOTAP_VHT_CODING_LDPC_USER0;
        }

        res.header[VHT_FLAGS_OFF] = flags;
        res.header[VHT_MCSNSS0_OFF] |= ((mcs_index << IEEE80211_RADIOTAP_VHT_MCS_SHIFT) & IEEE80211_RADIOTAP_VHT_MCS_MASK);
        res.header[VHT_MCSNSS0_OFF] |= ((vht_nss << IEEE80211_RADIOTAP_VHT_NSS_SHIFT) & IEEE80211_RADIOTAP_VHT_NSS_MASK);
    }

    return res;
}


void packet_injector(RawSocketInjector &t, vector<int> &rx_fd, int log_interval)
{
    int nfds = rx_fd.size();
    assert(nfds > 0);

    struct pollfd fds[nfds];
    memset(fds, '\0', sizeof(fds));

    for(size_t i=0; i < rx_fd.size(); i++)
    {
        fds[i].fd = rx_fd[i];
        fds[i].events = POLLIN;
    }

    uint32_t rxq_overflow = 0;
    uint64_t log_send_ts = get_time_ms();

    uint32_t count_p_incoming = 0;   // incoming udp packets (received + dropped due to rxq overflow)
    uint32_t count_b_incoming = 0;   // incoming udp bytes (received only)
    uint32_t count_p_dropped = 0;   // dropped due to rxq overflows or injection timeout
    uint32_t count_p_bad = 0; // injected large packets that were bad

    int start_fd_idx = 0;

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int poll_timeout = log_send_ts > cur_ts ? log_send_ts - cur_ts : 0;
        int rc = poll(fds, nfds, poll_timeout);

        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();

        if (cur_ts >= log_send_ts)  // log timeout expired
        {
            if(count_p_dropped)
            {
                fprintf(stderr, "%u packets dropped\n", count_p_dropped);
            }

            if(count_p_bad)
            {
                fprintf(stderr, "%u packets bad\n", count_p_bad);
            }

            count_p_incoming = 0;
            count_b_incoming = 0;
            count_p_dropped = 0;
            count_p_bad = 0;

            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        if (rc == 0) // poll timeout
        {
            continue;
        }

        // rc > 0: events detected
        // start from last fd index and reset it to zero
        int _tmp = start_fd_idx;
        start_fd_idx = 0;

        for(int i = _tmp; rc > 0; i = (i + 1) % nfds)
        {
            assert(i < nfds);

            if (fds[i].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (fds[i].revents & POLLIN)
            {
                uint8_t buf[MAX_DISTRIBUTION_PACKET_SIZE - sizeof(uint32_t) + 1];
                uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];
                rc -= 1;

                for(;;)
                {
                    ssize_t rsize;
                    uint32_t _fwmark;
                    int fd = fds[i].fd;

                    struct iovec iov[2] = {
                        // fwmark
                        {
                            .iov_base = (void*)&_fwmark,
                            .iov_len = sizeof(_fwmark),
                        },
                        // packet with radiotap header
                        {
                            .iov_base = (void*)buf,
                            .iov_len = sizeof(buf),
                        }
                    };

                    struct msghdr msghdr = { .msg_name = NULL,
                                             .msg_namelen = 0,
                                             .msg_iov = iov,
                                             .msg_iovlen = 2,
                                             .msg_control = &cmsgbuf,
                                             .msg_controllen = sizeof(cmsgbuf),
                                             .msg_flags = 0 };

                    memset(cmsgbuf, '\0', sizeof(cmsgbuf));

                    if ((rsize = recvmsg(fd, &msghdr, MSG_DONTWAIT)) < 0)
                    {
                        if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
                        break;
                    }

                    if (rsize < (ssize_t)MIN_DISTRIBUTION_PACKET_SIZE || rsize > (ssize_t)MAX_DISTRIBUTION_PACKET_SIZE)
                    {
                        count_p_bad += 1;
                        continue;
                    }

                    rsize -= sizeof(uint32_t);
                    count_p_incoming += 1;
                    count_b_incoming += rsize;

                    uint32_t cur_rxq_overflow = extract_rxq_overflow(&msghdr);
                    if (cur_rxq_overflow != rxq_overflow)
                    {
                        // Count dropped packets as possible incoming
                        count_p_dropped += (cur_rxq_overflow - rxq_overflow);
                        count_p_incoming += (cur_rxq_overflow - rxq_overflow);
                        rxq_overflow = cur_rxq_overflow;
                    }

                    cur_ts = get_time_ms();

                    t.inject_packet(i, buf, rsize, ntohl(_fwmark));

                    if (cur_ts >= log_send_ts)  // log timeout expired
                    {
                        // Save current index and go to outer loop
                        // We need to transmit all packets from the queue before tx card switch
                        start_fd_idx = i;
                        rc = 0;
                        break;
                    }
                }
            }
        }
    }
}

void injector_loop(int argc, char* const* argv, int optind, int srv_port, int rcv_buf, bool use_qdisc, int log_interval)
{
    vector<int> rx_fd;
    vector<string> wlans;
    for(int i = 0; optind + i < argc; i++)
    {
        int bind_port = srv_port != 0 ? srv_port + i : 0;
        int fd = open_udp_socket_for_rx(bind_port, rcv_buf);

        if (srv_port == 0)
        {
            struct sockaddr_in saddr;
            socklen_t saddr_size = sizeof(saddr);

            if (getsockname(fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
            {
                throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
            }
            bind_port = ntohs(saddr.sin_port);
            printf("%" PRIu64 "\tLISTEN_UDP\t%d:%x\n", get_time_ms(), bind_port, i);
        }
        fprintf(stderr, "Listen on %d for %s\n", bind_port, argv[optind + i]);
        rx_fd.push_back(fd);
        wlans.push_back(string(argv[optind + i]));
    }

    if (srv_port == 0)
    {
        printf("%" PRIu64 "\tLISTEN_UDP_END\n", get_time_ms());
        fflush(stdout);
    }

    auto t = RawSocketInjector(wlans, use_qdisc);
    packet_injector(t, rx_fd, log_interval);
}


int open_control_fd(int control_port)
{
    int control_fd = open_udp_socket_for_rx(control_port, 0, 0x7f000001);  // bind to 127.0.0.1 for security reasons

    if (control_port == 0)
    {
        struct sockaddr_in saddr;
        socklen_t saddr_size = sizeof(saddr);

        if (getsockname(control_fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
        {
            throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
        }
        control_port = ntohs(saddr.sin_port);
        printf("%" PRIu64 "\tLISTEN_UDP_CONTROL\t%d\n", get_time_ms(), control_port);
    }

    fprintf(stderr, "Listen on %d for management commands\n", control_port);
    return control_fd;
}

void local_loop(int argc, char* const* argv, int optind, int srv_port, int rcv_buf, int log_interval,
                int udp_port, int debug_port, int k, int n, const string &keypair, int fec_timeout,
                uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, bool use_qdisc, uint32_t fwmark,
                radiotap_header_t &radiotap_header, uint8_t frame_type, int control_port, bool mirror)
{
    vector<int> rx_fd;
    vector<string> wlans;
    vector<tags_item_t> tags;
    unique_ptr<Transmitter> t;

    for(int i = 0; optind + i < argc; i++)
    {
        int bind_port = udp_port != 0 ? udp_port + i : 0;
        int fd = open_udp_socket_for_rx(bind_port, rcv_buf);

        if (udp_port == 0)
        {
            struct sockaddr_in saddr;
            socklen_t saddr_size = sizeof(saddr);

            if (getsockname(fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
            {
                throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
            }
            bind_port = ntohs(saddr.sin_port);
            printf("%" PRIu64 "\tLISTEN_UDP\t%d:%x\n", get_time_ms(), bind_port, i);
        }
        fprintf(stderr, "Listen on %d for %s\n", bind_port, argv[optind + i]);
        rx_fd.push_back(fd);
        wlans.push_back(string(argv[optind + i]));
    }

    if (udp_port == 0)
    {
        printf("%" PRIu64 "\tLISTEN_UDP_END\n", get_time_ms());
        fflush(stdout);
    }

    if (debug_port)
    {
        fprintf(stderr, "Using %zu ports from %d for wlan emulation\n", wlans.size(), debug_port);
        t = unique_ptr<UdpTransmitter>(new UdpTransmitter(k, n, keypair, "127.0.0.1", debug_port, epoch, channel_id,
                                                          fec_delay, tags, use_qdisc, fwmark));
    }
    else
    {
        t = unique_ptr<RawSocketTransmitter>(new RawSocketTransmitter(k, n, keypair, epoch, channel_id, fec_delay, tags,
                                                                              wlans, radiotap_header, frame_type, use_qdisc, fwmark));
    }

    int control_fd = open_control_fd(control_port);
    data_source(t, rx_fd, control_fd, fec_timeout, mirror, log_interval);
}

void distributor_loop(int argc, char* const* argv, int optind, int srv_port, int rcv_buf, int log_interval,
                      int udp_port, int k, int n, const string &keypair, int fec_timeout,
                      uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, bool use_qdisc, uint32_t fwmark,
                      radiotap_header_t &radiotap_header, uint8_t frame_type, int control_port, bool mirror)
{
    vector<int> rx_fd;
    vector<pair<string, vector<uint16_t>>> remote_hosts;
    int port_idx = 0;

    set<string> hosts;

    for(int i = optind; i < argc; i++)
    {
        vector<uint16_t> remote_ports;
        char *p = argv[i];
        char *t = NULL;

        t = strsep(&p, ":");
        if (t == NULL) continue;

        string remote_host = string(t);

        if(hosts.count(remote_host))
        {
            throw runtime_error(string_format("Duplicate host %s", remote_host.c_str()));
        }

        hosts.insert(remote_host);

        for(int j=0; (t=strsep(&p, ",")) != NULL; j++)
        {
            uint16_t remote_port = atoi(t);
            int bind_port = (udp_port != 0) ? (udp_port + port_idx++) : 0;
            int fd = open_udp_socket_for_rx(bind_port, rcv_buf);

            if (udp_port == 0)
            {
                struct sockaddr_in saddr;
                socklen_t saddr_size = sizeof(saddr);

                if (getsockname(fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
                {
                    throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
                }
                bind_port = ntohs(saddr.sin_port);

                uint64_t wlan_id = (uint64_t)ntohl(inet_addr(remote_host.c_str())) << 24  | j;
                printf("%" PRIu64 "\tLISTEN_UDP\t%d:%" PRIx64 "\n", get_time_ms(), bind_port, wlan_id);
            }

            fprintf(stderr, "Listen on %d for %s:%d\n", bind_port, remote_host.c_str(), remote_port);

            rx_fd.push_back(fd);
            remote_ports.push_back(remote_port);
        }

        remote_hosts.push_back(pair<string, vector<uint16_t>>(remote_host, remote_ports));
    }

    if (udp_port == 0)
    {
        printf("%" PRIu64 "\tLISTEN_UDP_END\n", get_time_ms());
        fflush(stdout);
    }

    vector<tags_item_t> tags;
    unique_ptr<Transmitter> t = unique_ptr<RemoteTransmitter>(new RemoteTransmitter(k, n, keypair, epoch, channel_id, fec_delay, tags,
                                                                                    remote_hosts, radiotap_header, frame_type, use_qdisc, fwmark));

    int control_fd = open_control_fd(control_port);
    data_source(t, rx_fd, control_fd, fec_timeout, mirror, log_interval);
}

int main(int argc, char * const *argv)
{
    int opt;
    uint8_t k=8, n=12, radio_port=0;
    uint32_t fec_delay = 0;
    uint32_t link_id = 0x0;
    uint64_t epoch = 0;
    int srv_port = 10000;
    int udp_port=5600;
    int control_port=0;
    int log_interval = 1000;

    int bandwidth = 20;
    int short_gi = 0;
    int stbc = 0;
    int ldpc = 0;
    int mcs_index = 1;
    int vht_nss = 1;
    int debug_port = 0;
    int fec_timeout = 0;
    int rcv_buf = 0;
    bool mirror = false;
    bool vht_mode = false;
    string keypair = "tx.key";
    uint8_t frame_type = FRAME_TYPE_DATA;
    bool use_qdisc = false;
    uint32_t fwmark = 0;
    tx_mode_t tx_mode = LOCAL;

    while ((opt = getopt(argc, argv, "dI:K:k:n:u:p:F:l:B:G:S:L:M:N:D:T:i:e:R:f:mVQP:C:")) != -1) {
        switch (opt) {
        case 'I':
            tx_mode = INJECTOR;
            srv_port = atoi(optarg);
            break;
        case 'd':
            tx_mode = DISTRIBUTOR;
            break;
        case 'K':
            keypair = optarg;
            break;
        case 'k':
            k = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'u':
            udp_port = atoi(optarg);
            break;
        case 'p':
            radio_port = atoi(optarg);
            break;
        case 'F':
            fec_delay = atoi(optarg);
            break;
        case 'R':
            rcv_buf = atoi(optarg);
            break;
        case 'B':
            bandwidth = atoi(optarg);
            // Force VHT mode for bandwidth >= 80
            if (bandwidth >= 80) {
                vht_mode = true;
            }
            break;
        case 'G':
            short_gi = (optarg[0] == 's' || optarg[0] == 'S') ? 1 : 0;
            break;
        case 'S':
            stbc = atoi(optarg);
            break;
        case 'L':
            ldpc = atoi(optarg);
            break;
        case 'M':
            mcs_index = atoi(optarg);
            break;
        case 'N':
            vht_nss = atoi(optarg);
            break;
        case 'D':
            debug_port = atoi(optarg);
            break;
        case 'T':
            fec_timeout = atoi(optarg);
            break;
        case 'l':
            log_interval = atoi(optarg);
            break;
        case 'i':
            link_id = ((uint32_t)atoi(optarg)) & 0xffffff;
            break;
        case 'e':
            epoch = atoll(optarg);
            break;
        case 'm':
            mirror = true;
            break;
        case 'V':
            vht_mode = true;
            break;
        case 'f':
            if (strcmp(optarg, "data") == 0)
            {
                fprintf(stderr, "Using data frames\n");
                frame_type = FRAME_TYPE_DATA;
            }
            else if (strcmp(optarg, "rts") == 0)
            {
                fprintf(stderr, "Using rts frames\n");
                frame_type = FRAME_TYPE_RTS;
            }
            else
            {
                fprintf(stderr, "Invalid frame type: %s\n", optarg);
                exit(1);
            }
            break;
        case 'Q':
            use_qdisc = true;
            break;
        case 'P':
            fwmark = (uint32_t)atoi(optarg);
            break;
        case 'C':
            control_port = atoi(optarg);
            break;
        default: /* '?' */
        show_usage:
            fprintf(stderr, "Local TX: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-R rcv_buf] [-p radio_port] [-F fec_delay] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-N VHT_NSS]\n"
                            "             [-T fec_timeout] [-l log_interval] [-e epoch] [-i link_id] [-f { data | rts }] [-m] [-V] [-Q] [-P fwmark] [-C control_port] interface1 [interface2] ...\n",
                    argv[0]);
            fprintf(stderr, "TX distributor: %s -d [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-R rcv_buf] [-p radio_port] [-F fec_delay] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-N VHT_NSS]\n"
                            "                      [-T fec_timeout] [-l log_interval] [-e epoch] [-i link_id] [-f { data | rts }] [-m] [-V] [-Q] [-P fwmark] [-C control_port] host1:port1,port2,... [host2:port1,port2,...] ...\n",
                    argv[0]);
            fprintf(stderr, "TX injector: %s -I port [-Q] [-R rcv_buf] [-l log_interval] interface1 [interface2] ...\n",
                    argv[0]);
            fprintf(stderr, "Default: K='%s', k=%d, n=%d, fec_delay=%u [us], udp_port=%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d vht_nss=%d, vht_mode=%d, fec_timeout=%d, log_interval=%d, rcv_buf=system_default, frame_type=data, mirror=false, use_qdisc=false, fwmark=%u, control_port=%d\n",
                    keypair.c_str(), k, n, fec_delay, udp_port, link_id, radio_port, epoch, bandwidth, short_gi ? "short" : "long", stbc, ldpc, mcs_index, vht_nss, vht_mode, fec_timeout, log_interval, fwmark, control_port);
            fprintf(stderr, "Radio MTU: %lu\n", (unsigned long)MAX_PAYLOAD_SIZE);
            fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
            fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    {
        int fd;
        int c;

        if ((fd = open("/dev/random", O_RDONLY)) != -1) {
            if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
                fprintf(stderr, "This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                        "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                        "On virtualized Linux environments, also consider using virtio-rng.\n"
                        "The service will not start until enough entropy has been collected.\n");
            }
            (void) close(fd);
        }
    }

    if (sodium_init() < 0)
    {
        fprintf(stderr, "Libsodium init failed\n");
        return 1;
    }

    try
    {
        auto radiotap_header = init_radiotap_header(stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss);
        uint32_t channel_id = (link_id << 8) + radio_port;

        switch(tx_mode)
        {
        case INJECTOR:
            injector_loop(argc, argv, optind, srv_port, rcv_buf, use_qdisc, log_interval);
            break;

        case LOCAL:
            local_loop(argc, argv, optind, srv_port, rcv_buf, log_interval,
                       udp_port, debug_port, k, n, keypair, fec_timeout,
                       epoch, channel_id, fec_delay, use_qdisc, fwmark,
                       radiotap_header, frame_type, control_port, mirror);
            break;


        case DISTRIBUTOR:
            distributor_loop(argc, argv, optind, srv_port, rcv_buf, log_interval,
                             udp_port, k, n, keypair, fec_timeout,
                             epoch, channel_id, fec_delay, use_qdisc, fwmark,
                             radiotap_header, frame_type, control_port, mirror);
            break;

        default:
            assert(0);
        }
    }
    catch(runtime_error &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
