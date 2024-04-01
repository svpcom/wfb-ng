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
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/random.h>
#include <inttypes.h>

#include <string>
#include <memory>
#include <vector>

extern "C"
{
#include "fec.h"
}

#include "wifibroadcast.hpp"
#include "tx.hpp"

using namespace std;

Transmitter::Transmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id) : \
    fec_k(k), fec_n(n), block_idx(0),
    fragment_idx(0),
    max_packet_size(0),
    epoch(epoch),
    channel_id(channel_id)
{
    fec_p = fec_new(fec_k, fec_n);

    block = new uint8_t*[fec_n];
    for(int i=0; i < fec_n; i++)
    {
        block[i] = new uint8_t[MAX_FEC_PAYLOAD];
    }

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

    make_session_key();
}

Transmitter::~Transmitter()
{
    for(int i=0; i < fec_n; i++)
    {
        delete block[i];
    }
    delete block;

    fec_free(fec_p);
}


void Transmitter::make_session_key(void)
{
    // init session key
    randombytes_buf(session_key, sizeof(session_key));

    // fill packet header
    wsession_hdr_t *session_hdr = (wsession_hdr_t *)session_key_packet;
    session_hdr->packet_type = WFB_PACKET_KEY;

    randombytes_buf(session_hdr->session_nonce, sizeof(session_hdr->session_nonce));

    // fill packet contents
    wsession_data_t session_data = { .epoch = htobe64(epoch),
                                     .channel_id = htobe32(channel_id),
                                     .fec_type = WFB_FEC_VDM_RS,
                                     .k = (uint8_t)fec_k,
                                     .n = (uint8_t)fec_n,
                                   };

    memcpy(session_data.session_key, session_key, sizeof(session_key));

    if (crypto_box_easy(session_key_packet + sizeof(wsession_hdr_t),
                        (uint8_t*)&session_data, sizeof(session_data),
                        session_hdr->session_nonce, rx_publickey, tx_secretkey) != 0)
    {
        throw runtime_error("Unable to make session key!");
    }
}

RawSocketTransmitter::RawSocketTransmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, const vector<string> &wlans) : \
    Transmitter(k, n, keypair, epoch, channel_id),
    channel_id(channel_id),
    current_output(0),
    ieee80211_seq(0)
{
    for(auto it=wlans.begin(); it!=wlans.end(); it++)
    {
        int fd = socket(PF_PACKET, SOCK_RAW, 0);
        if (fd < 0)
        {
            throw runtime_error(string_format("Unable to open PF_PACKET socket: %s", strerror(errno)));
        }

        const int optval = 1;
        if(setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, (const void *)&optval , sizeof(optval)) !=0)
        {
            close(fd);
            throw runtime_error(string_format("Unable to set PACKET_QDISC_BYPASS: %s", strerror(errno)));
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

        if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
        {
            close(fd);
            throw runtime_error(string_format("Unable to bind to %s: %s", it->c_str(), strerror(errno)));
        }

        sockfds.push_back(fd);
    }
}

void RawSocketTransmitter::inject_packet(const uint8_t *buf, size_t size)
{
    assert(size <= MAX_FORWARDER_PACKET_SIZE);

    uint8_t ieee_hdr[sizeof(ieee80211_header)];
    memcpy(ieee_hdr, ieee80211_header, sizeof(ieee80211_header));

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
            { .iov_base = (void*)radiotap_header,
              .iov_len = sizeof(radiotap_header)
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
        int rc = sendmsg(sockfds[current_output], &msghdr, 0);

        if (rc < 0 && errno != ENOBUFS)
        {
            throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
        }

        uint64_t key = (uint64_t)(current_output) << 8 | (uint64_t)0xff;
        antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0);
    }
    else
    {
        // Mirror mode - transmit packet via all cards
        // Use only for different frequency channels
        int i = 0;
        for(auto it=sockfds.begin(); it != sockfds.end(); it++, i++)
        {
            uint64_t start_us = get_time_us();
            int rc = sendmsg(*it, &msghdr, 0);

            if (rc < 0 && errno != ENOBUFS)
            {
                throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
            }

            uint64_t key = (uint64_t)(i) << 8 | (uint64_t)0xff;
            antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0);
        }
    }

}

void RawSocketTransmitter::dump_stats(FILE *fp, uint64_t ts, uint32_t &injected, uint32_t &dropped)
{
    for(tx_antenna_stat_t::iterator it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        fprintf(fp, "%" PRIu64 "\tTX_ANT\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                ts, it->first,
                it->second.count_injected, it->second.count_dropped,
                it->second.latency_min,
                it->second.latency_sum / (it->second.count_injected + it->second.count_dropped),
                it->second.latency_max);

        injected += it->second.count_injected;
        dropped += it->second.count_dropped;
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
    inject_packet((uint8_t*)session_key_packet, sizeof(session_key_packet));
}

bool Transmitter::send_packet(const uint8_t *buf, size_t size, uint8_t flags)
{
    assert(size <= MAX_PAYLOAD_SIZE);

    // FEC-only packets are only for closing already opened blocks
    if (fragment_idx == 0 && flags & WFB_PACKET_FEC_ONLY)
    {
        return false;
    }

    wpacket_hdr_t *packet_hdr = (wpacket_hdr_t*)block[fragment_idx];

    packet_hdr->flags = flags;
    packet_hdr->packet_size = htobe16(size);

    memcpy(block[fragment_idx] + sizeof(wpacket_hdr_t), buf, size);
    memset(block[fragment_idx] + sizeof(wpacket_hdr_t) + size, '\0', MAX_FEC_PAYLOAD - (sizeof(wpacket_hdr_t) + size));

    send_block_fragment(sizeof(wpacket_hdr_t) + size);
    max_packet_size = max(max_packet_size, sizeof(wpacket_hdr_t) + size);
    fragment_idx += 1;

    if (fragment_idx < fec_k)  return true;

    fec_encode(fec_p, (const uint8_t**)block, block + fec_k, max_packet_size);
    while (fragment_idx < fec_n)
    {
        send_block_fragment(max_packet_size);
        fragment_idx += 1;
    }
    block_idx += 1;
    fragment_idx = 0;
    max_packet_size = 0;

    // Generate new session key after MAX_BLOCK_IDX blocks
    if (block_idx > MAX_BLOCK_IDX)
    {
        make_session_key();
        send_session_key();
        block_idx = 0;
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

void data_source(shared_ptr<Transmitter> &t, vector<int> &rx_fd, int fec_timeout, bool mirror, int log_interval)
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

    uint64_t session_key_announce_ts = 0;
    uint32_t rxq_overflow = 0;
    uint64_t log_send_ts = 0;
    uint64_t fec_close_ts = fec_timeout > 0 ? get_time_ms() + fec_timeout : 0;
    uint32_t count_p_fec_timeouts = 0; // empty packets sent to close fec block due to timeout
    uint32_t count_p_incoming = 0;   // incoming udp packets (received + dropped due to rxq overflow)
    uint32_t count_p_injected = 0;  // successfully injected (include additional fec packets)
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

        int rc = poll(fds, nfds, poll_timeout);

        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();

        if (cur_ts >= log_send_ts)  // log timeout expired
        {
            t->dump_stats(stdout, cur_ts, count_p_injected, count_p_dropped);

            fprintf(stdout, "%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u\n",
                    cur_ts, count_p_fec_timeouts, count_p_incoming, count_p_injected, count_p_dropped, count_p_truncated);
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
            count_p_injected = 0;
            count_p_dropped = 0;
            count_p_truncated = 0;

            log_send_ts = cur_ts + log_interval;
        }

        if (rc == 0) // poll timeout
        {
            // close fec only if no data packets and fec timeout expired
            if (fec_timeout > 0 && cur_ts >= fec_close_ts)
            {
                if(!t->send_packet(NULL, 0, WFB_PACKET_FEC_ONLY))
                {
                    count_p_fec_timeouts += 1;
                }
                fec_close_ts = cur_ts + fec_timeout;
            }
            continue;
        }

        // rc > 0: events detected

        // start from last fd index and reset it to zero
        int i = start_fd_idx;
        for(start_fd_idx = 0; rc > 0; i++)
        {
            if (fds[i % nfds].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (fds[i % nfds].revents & POLLIN)
            {
                uint8_t buf[MAX_PAYLOAD_SIZE + 1];
                ssize_t rsize;
                uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];
                rc -= 1;

                t->select_output(mirror ? -1 : (i % nfds));

                for(;;)
                {
                    int fd = fds[i % nfds].fd;
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

                    uint64_t cur_ts = get_time_ms();

                    if (cur_ts >= session_key_announce_ts)
                    {
                        // Announce session key
                        t->send_session_key();
                        session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_MSEC;
                    }

                    t->send_packet(buf, rsize, 0);

                    if (cur_ts >= log_send_ts)  // log timeout expired
                    {
                        // We need to transmit all packets from the queue before tx card switch
                        start_fd_idx = i % nfds;
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


int main(int argc, char * const *argv)
{
    int opt;
    uint8_t k=8, n=12, radio_port=0;
    uint32_t link_id = 0x0;
    uint64_t epoch = 0;
    int udp_port=5600;
    int log_interval = 1000;

    int bandwidth = 20;
    int short_gi = 0;
    int stbc = 0;
    int ldpc = 0;
    int mcs_index = 1;
    int debug_port = 0;
    int fec_timeout = 0;
    int rcv_buf = 0;
    bool mirror = false;
    string keypair = "tx.key";

    while ((opt = getopt(argc, argv, "K:k:n:u:p:l:B:G:S:L:M:D:T:i:e:R:f:m")) != -1) {
        switch (opt) {
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
        case 'R':
            rcv_buf = atoi(optarg);
            break;
        case 'B':
            bandwidth = atoi(optarg);
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
        case 'f':
            if (strcmp(optarg, "data") == 0)
            {
                fprintf(stderr, "Using data frames\n");
                ieee80211_header[0] = FRAME_TYPE_DATA;
            }
            else if (strcmp(optarg, "rts") == 0)
            {
                fprintf(stderr, "Using rts frames\n");
                ieee80211_header[0] = FRAME_TYPE_RTS;
            }
            else
            {
                fprintf(stderr, "Invalid frame type: %s\n", optarg);
                exit(1);
            }
            break;
        default: /* '?' */
        show_usage:
            fprintf(stderr, "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-R rcv_buf] [-p radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-T fec_timeout] [-l log_interval] [-e epoch] [-i link_id] [-f { data | rts }] [ -m ] interface1 [interface2] ...\n",
                    argv[0]);
            fprintf(stderr, "Default: K='%s', k=%d, n=%d, udp_port=%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d, fec_timeout=%d, log_interval=%d, rcv_buf=system_default, frame_type=data, mirror=false\n",
                    keypair.c_str(), k, n, udp_port, link_id, radio_port, epoch, bandwidth, short_gi ? "short" : "long", stbc, ldpc, mcs_index, fec_timeout, log_interval);
            fprintf(stderr, "Radio MTU: %lu\n", (unsigned long)MAX_PAYLOAD_SIZE);
            fprintf(stderr, "WFB-ng version " WFB_VERSION "\n");
            fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    // Set flags in radiotap header
    {
        uint8_t flags = 0;
        switch(bandwidth) {
        case 20:
            flags |= IEEE80211_RADIOTAP_MCS_BW_20;
            break;
        case 40:
            flags |= IEEE80211_RADIOTAP_MCS_BW_40;
            break;
        default:
            fprintf(stderr, "Unsupported bandwidth: %d\n", bandwidth);
            exit(1);
        }

        if (short_gi)
        {
            flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }

        switch(stbc) {
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
            fprintf(stderr, "Unsupported STBC type: %d\n", stbc);
            exit(1);
        }

        if (ldpc)
        {
            flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
        }

        radiotap_header[MCS_FLAGS_OFF] = flags;
        radiotap_header[MCS_IDX_OFF] = mcs_index;
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
        vector<int> rx_fd;
        vector<string> wlans;
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
                printf("%" PRIu64 "\tLISTEN_UDP\t%d:%s\n", get_time_ms(), bind_port, argv[optind + i]);
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

        shared_ptr<Transmitter> t;

        uint32_t channel_id = (link_id << 8) + radio_port;

        if (debug_port)
        {
            fprintf(stderr, "Using %zu ports from %d for wlan emulation\n", wlans.size(), debug_port);
            t = shared_ptr<UdpTransmitter>(new UdpTransmitter(k, n, keypair, "127.0.0.1", debug_port, epoch, channel_id));
        } else {
            t = shared_ptr<RawSocketTransmitter>(new RawSocketTransmitter(k, n, keypair, epoch, channel_id, wlans));
        }

        data_source(t, rx_fd, fec_timeout, mirror, log_interval);
    }catch(runtime_error &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
