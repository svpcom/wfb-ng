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

#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <linux/random.h>

extern "C"
{
#include "ieee80211_radiotap.h"
#include "fec.h"
}

#include <string>
#include <memory>

#include "wifibroadcast.hpp"
#include "rx.hpp"

using namespace std;


Receiver::Receiver(const char *wlan, int wlan_idx, uint32_t channel_id, BaseAggregator *agg, int rcv_buf_size) : wlan_idx(wlan_idx), agg(agg)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    ppcap = pcap_create(wlan, errbuf);

    if (ppcap == NULL){
        throw runtime_error(string_format("Unable to open interface %s in pcap: %s", wlan, errbuf));
    }

    try
    {
        if (rcv_buf_size > 0 && pcap_set_buffer_size(ppcap, rcv_buf_size) != 0) throw runtime_error("set_buffer_size failed");
        if (pcap_set_snaplen(ppcap, MAX_PCAP_PACKET_SIZE) != 0) throw runtime_error("set_snaplen failed");
        if (pcap_set_promisc(ppcap, 1) != 0) throw runtime_error("set_promisc failed");
        if (pcap_set_timeout(ppcap, -1) != 0) throw runtime_error("set_timeout failed");
        if (pcap_set_immediate_mode(ppcap, 1) != 0) throw runtime_error(string_format("pcap_set_immediate_mode failed: %s", pcap_geterr(ppcap)));
        if (pcap_activate(ppcap) !=0) throw runtime_error(string_format("pcap_activate failed: %s", pcap_geterr(ppcap)));
        if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw runtime_error(string_format("set_nonblock failed: %s", errbuf));

        int link_encap = pcap_datalink(ppcap);
        struct bpf_program bpfprogram;
        string program;

        if (link_encap != DLT_IEEE802_11_RADIO) {
            throw runtime_error(string_format("unknown encapsulation on %s", wlan));
        }

        program = string_format("ether[0x0a:2]==0x5742 && ether[0x0c:4] == 0x%08x", channel_id);

        if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
            throw runtime_error(string_format("Unable to compile %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }

        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            throw runtime_error(string_format("Unable to set filter %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }

        pcap_freecode(&bpfprogram);
        fd = pcap_get_selectable_fd(ppcap);
    }
    catch(...)
    {
        pcap_close(ppcap);
        throw;
    }
}


Receiver::~Receiver()
{
    close(fd);
    pcap_close(ppcap);
}


void Receiver::loop_iter(void)
{
    for(;;) // loop while incoming queue is not empty
    {
        struct pcap_pkthdr hdr;
        const uint8_t* pkt = pcap_next(ppcap, &hdr);

        if (pkt == NULL) {
            break;
        }

        int pktlen = hdr.caplen;
        // int pkt_rate = 0
        int ant_idx = 0;
        uint32_t freq = 0;
        uint8_t antenna[RX_ANT_MAX];
        int8_t rssi[RX_ANT_MAX];
        int8_t noise[RX_ANT_MAX];
        uint8_t flags = 0;
        bool self_injected = false;
        uint8_t mcs_index = 0;
        uint8_t bandwidth = 20;

        struct ieee80211_radiotap_iterator iterator;
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header*)pkt, pktlen, NULL);

        // Fill all antenna slots with 0xff (unused)
        memset(antenna, 0xff, sizeof(antenna));
        // Fill all rssi slots with minimum value
        memset(rssi, SCHAR_MIN, sizeof(rssi));
        // Fill all noise slots with maximum value
        memset(noise, SCHAR_MAX, sizeof(noise));

        while (ret == 0 && ant_idx < RX_ANT_MAX) {
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

            case IEEE80211_RADIOTAP_ANTENNA:
                antenna[ant_idx] = *(uint8_t*)(iterator.this_arg);
                ant_idx += 1;
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                // drop channel flags - they are redundant for freq to chan convertion
                freq = le32toh(*(uint32_t*)(iterator.this_arg)) & 0xffff;
                break;

            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                rssi[ant_idx] = *(int8_t*)(iterator.this_arg);
                break;

            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                noise[ant_idx] = *(int8_t*)(iterator.this_arg);
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                flags = *(uint8_t*)(iterator.this_arg);
                break;

            case IEEE80211_RADIOTAP_TX_FLAGS:
                self_injected = true;
                break;

            case IEEE80211_RADIOTAP_MCS:
            {
                /* u8,u8,u8 */

                uint8_t mcs_have = iterator.this_arg[0];

                if (mcs_have & IEEE80211_RADIOTAP_MCS_HAVE_MCS)
                {
                    mcs_index = iterator.this_arg[2] & 0x7f;
                }

                if ((mcs_have & 1) && (iterator.this_arg[1] & 1))
                {
                    bandwidth = 40;
                }
            }
            break;

            case IEEE80211_RADIOTAP_VHT:
            {
		/* u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], u8 coding, u8 group_id, u16 partial_aid */
                u8 known = iterator.this_arg[0];

                if(known & 0x40)
                {
                    int bwidth = iterator.this_arg[3] & 0x1f;
                    if(bwidth >= 1 && bwidth <= 3)
                    {
                        bandwidth = 40;
                    }
                    else if(bwidth >= 4 && bwidth <= 10)
                    {
                        bandwidth = 80;
                    }
                }
                mcs_index = (iterator.this_arg[4] >> 4) & 0x0f;
            }
            break;

            default:
                break;
            }
        }  /* while more rt headers */

        if (ret != -ENOENT && ant_idx < RX_ANT_MAX){
            WFB_ERR("Error parsing radiotap header!\n");
            continue;
        }

        if (self_injected)
        {
            //ignore self injected frames
            continue;
        }

        if (flags & IEEE80211_RADIOTAP_F_FCS)
        {
            pktlen -= 4;
        }

        if (flags & IEEE80211_RADIOTAP_F_BADFCS)
        {
            WFB_ERR("Got packet with bad fsc\n");
            continue;
        }

        /* discard the radiotap header part */
        pkt += iterator._max_length;
        pktlen -= iterator._max_length;

        if (pktlen > (int)sizeof(ieee80211_header))
        {
            agg->process_packet(pkt + sizeof(ieee80211_header), pktlen - sizeof(ieee80211_header),
                                wlan_idx, antenna, rssi, noise, freq, mcs_index, bandwidth, NULL);
        } else {
            WFB_ERR("Short packet (ieee header)\n");
            continue;
        }
    }
}

Aggregator::Aggregator(const string &client_addr,
                       int client_port,
                       const string &keypair,
                       uint64_t epoch,
                       uint32_t channel_id,
                       std::optional<std::function<void(uint8_t*, uint16_t)>> callback)
        : count_p_all(0), count_b_all(0), count_p_dec_err(0), count_p_dec_ok(0), count_p_fec_recovered(0),
          count_p_lost(0), count_p_bad(0), count_p_override(0), count_p_outgoing(0), count_b_outgoing(0), fec_p(NULL),
          fec_k(-1), fec_n(-1), seq(0), rx_ring{}, rx_ring_front(0), rx_ring_alloc(0), last_known_block((uint64_t)-1),
          epoch(epoch), channel_id(channel_id), callback(callback)
{
    if (!callback)
    {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        memset(&saddr, '\0', sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short)client_port);
    }

    memset(session_key, '\0', sizeof(session_key));

    FILE *fp;
    if((fp = fopen(keypair.c_str(), "r")) == NULL)
    {
        throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
    }
    if (fread(rx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read rx secret key: %s", strerror(errno)));
    }
    if (fread(tx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read tx public key: %s", strerror(errno)));
    }
    fclose(fp);
}


Aggregator::~Aggregator()
{
    if (fec_p != NULL)
    {
        deinit_fec();
    }
    if (sockfd >= 0)
    {
        close(sockfd);
    }
}

void Aggregator::init_fec(int k, int n)
{
    assert(fec_p == NULL);
    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    fec_k = k;
    fec_n = n;
    fec_p = fec_new(fec_k, fec_n);

    rx_ring_front = 0;
    rx_ring_alloc = 0;
    last_known_block = (uint64_t)-1;
    seq = 0;

    for(int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++)
    {
        rx_ring[ring_idx].block_idx = 0;
        rx_ring[ring_idx].fragment_to_send_idx = 0;
        rx_ring[ring_idx].has_fragments = 0;
        rx_ring[ring_idx].fragments = new uint8_t*[fec_n];
        for(int i=0; i < fec_n; i++)
        {
            rx_ring[ring_idx].fragments[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
        rx_ring[ring_idx].fragment_map = new size_t[fec_n];
        memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(size_t));
    }
}

void Aggregator::deinit_fec(void)
{
    assert(fec_p != NULL);

    for(int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++)
    {
        delete[] rx_ring[ring_idx].fragment_map;
        rx_ring[ring_idx].fragment_map = NULL;
        for(int i=0; i < fec_n; i++)
        {
            delete[] rx_ring[ring_idx].fragments[i];
        }
        delete[] rx_ring[ring_idx].fragments;
        rx_ring[ring_idx].fragments = NULL;
    }

    fec_free(fec_p);
    fec_p = NULL;
    fec_k = -1;
    fec_n = -1;
}


Forwarder::Forwarder(const string &client_addr, int client_port)
{
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
    saddr.sin_port = htons((unsigned short)client_port);
}


void Forwarder::process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                               const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                               uint8_t bandwidth, sockaddr_in *sockaddr)
{
    wrxfwd_t fwd_hdr = { .wlan_idx = wlan_idx,
                         .freq = htons(freq),
                         .mcs_index = mcs_index,
                         .bandwidth = bandwidth };

    memcpy(fwd_hdr.antenna, antenna, RX_ANT_MAX * sizeof(uint8_t));
    memcpy(fwd_hdr.rssi, rssi, RX_ANT_MAX * sizeof(int8_t));
    memcpy(fwd_hdr.noise, noise, RX_ANT_MAX * sizeof(int8_t));

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
                             .msg_flags = 0 };

    sendmsg(sockfd, &msghdr, MSG_DONTWAIT);
}


Forwarder::~Forwarder()
{
    close(sockfd);
}

int Aggregator::rx_ring_push(void)
{
    if(rx_ring_alloc < RX_RING_SIZE)
    {
        int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
        rx_ring_alloc += 1;
        return idx;
    }

    /*
      Ring overflow. This means that there are more unfinished blocks than ring size
      Possible solutions:
      1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
         Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
      2. Reduce packet injection speed or try to unify RX hardware.
    */

    WFB_DBG("AGG: Override block 0x%" PRIx64 " flush %d fragments\n", rx_ring[rx_ring_front].block_idx, rx_ring[rx_ring_front].has_fragments);

    count_p_override += 1;

    for(int f_idx=rx_ring[rx_ring_front].fragment_to_send_idx; f_idx < fec_k; f_idx++)
    {
        if(rx_ring[rx_ring_front].fragment_map[f_idx])
        {
            send_packet(rx_ring_front, f_idx);
        }
    }

    // override last item in ring
    int ring_idx = rx_ring_front;
    rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
    return ring_idx;
}


int Aggregator::get_block_ring_idx(uint64_t block_idx)
{
    // check if block is already in the ring
    for(int i = rx_ring_front, c = rx_ring_alloc; c > 0; i = modN(i + 1, RX_RING_SIZE), c--)
    {
        if (rx_ring[i].block_idx == block_idx) return i;
    }

    // check if block is already known and not in the ring then it is already processed
    if (last_known_block != (uint64_t)-1 && block_idx <= last_known_block)
    {
        return -1;
    }

    int new_blocks = (int)min(last_known_block != (uint64_t)-1 ? block_idx - last_known_block : 1, (uint64_t)RX_RING_SIZE);
    assert (new_blocks > 0);

    last_known_block = block_idx;
    int ring_idx = -1;

    for(int i = 0; i < new_blocks; i++)
    {
        ring_idx = rx_ring_push();
        rx_ring[ring_idx].block_idx = block_idx + i + 1 - new_blocks;
        rx_ring[ring_idx].fragment_to_send_idx = 0;
        rx_ring[ring_idx].has_fragments = 0;
        memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(size_t));
    }
    return ring_idx;
}

void Aggregator::dump_stats(void)
{
    //timestamp in ms
    uint64_t ts = get_time_ms();

    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        IPC_MSG("%" PRIu64 "\tRX_ANT\t%u:%u:%u\t%" PRIx64 "\t%d" ":%d:%d:%d" ":%d:%d:%d\n",
                ts, it->first.freq, it->first.mcs_index, it->first.bandwidth, it->first.antenna_id, it->second.count_all,
                it->second.rssi_min, it->second.rssi_sum / it->second.count_all, it->second.rssi_max,
                it->second.snr_min, it->second.snr_sum / it->second.count_all, it->second.snr_max);
    }

    IPC_MSG("%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u:%u:%u:%u\n", ts, count_p_all, count_b_all, count_p_dec_err,
            count_p_dec_ok, count_p_fec_recovered, count_p_lost, count_p_bad, count_p_outgoing, count_b_outgoing);
    IPC_MSG_SEND();

    if(count_p_override)
    {
        WFB_ERR("%u block overrides\n", count_p_override);
    }

    if(count_p_lost)
    {
        WFB_ERR("%u packets lost\n", count_p_lost);
    }

    clear_stats();
}


void Aggregator::log_rssi(const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi, const int8_t *noise,
                          uint16_t freq, uint8_t mcs_index, uint8_t bandwidth)
{
    for(int i = 0; i < RX_ANT_MAX && ant[i] != 0xff; i++)
    {
        // antenna_id: addr + port + wlan_idx + ant
        rxAntennaKey key = {.freq = freq,
                            .antenna_id = 0,
                            .mcs_index=mcs_index,
                            .bandwidth=bandwidth};

        if (sockaddr != NULL && sockaddr->sin_family == AF_INET)
        {
            // We ignore port here because for the one host (wlan_idx, antenna_id) will be unique key for all forwarder processes.
            key.antenna_id = ((uint64_t)ntohl(sockaddr->sin_addr.s_addr) << 32);
        }

        key.antenna_id |= ((uint64_t)wlan_idx << 8 | (uint64_t)ant[i]);

        antenna_stat[key].log_rssi(rssi[i], noise[i]);
    }
}

// cppcheck-suppress unusedFunction
int Aggregator::get_tag(const void *buf, size_t size, uint8_t tag_id, void *value, size_t value_size)
{
    tlv_hdr_t *p = (tlv_hdr_t*)buf;
    void *end = (uint8_t*)buf + size;

    while((void*)(p + 1) <= end)
    {
        if(p->id != tag_id)
        {
            p = (tlv_hdr_t*)((uint8_t*)(p + 1) + p->len);
            continue;
        }
        if(p->len > value_size) return -1;
        if(p->value + p->len > end) return -1;
        memcpy(value, p->value, p->len);
        return p->len;
    }

    return -1;
}

void Aggregator::process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                                const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                                uint8_t bandwidth, sockaddr_in *sockaddr)
{
    uint8_t session_tmp[MAX_SESSION_PACKET_SIZE - crypto_box_MACBYTES - sizeof(wsession_hdr_t)];
    wsession_data_t* new_session_data = NULL;
    //size_t new_session_tags_size = 0;

    count_p_all += 1;
    count_b_all += size;

    if(size == 0) return;

    if (size > MAX_FORWARDER_PACKET_SIZE)
    {
        WFB_ERR("Long packet (fec payload)\n");
        count_p_bad += 1;
        return;
    }

    switch(buf[0])
    {
    case WFB_PACKET_DATA:
        if(size < sizeof(wblock_hdr_t) + crypto_aead_chacha20poly1305_ABYTES + sizeof(wpacket_hdr_t))
        {
            WFB_ERR("Short packet (fec header)\n");
            count_p_bad += 1;
            return;
        }
        break;

    case WFB_PACKET_SESSION:
        new_session_data = (wsession_data_t*)session_tmp;

        if(size < sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES || \
           size > MAX_SESSION_PACKET_SIZE)
        {
            WFB_ERR("Invalid session key packet\n");
            count_p_bad += 1;
            return;
        }

        if(crypto_box_open_easy((uint8_t*)session_tmp,
                                buf + sizeof(wsession_hdr_t),
                                size - sizeof(wsession_hdr_t),
                                ((wsession_hdr_t*)buf)->session_nonce,
                                tx_publickey, rx_secretkey) != 0)
        {
            WFB_ERR("Unable to decrypt session key\n");
            count_p_dec_err += 1;
            return;
        }

        //new_session_tags_size = size - (sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES);

        if (be64toh(new_session_data->epoch) < epoch)
        {
            WFB_ERR("Session epoch doesn't match: %" PRIu64 " < %" PRIu64 "\n", be64toh(new_session_data->epoch), epoch);
            count_p_dec_err += 1;
            return;
        }

        if (be32toh(new_session_data->channel_id) != channel_id)
        {
            WFB_ERR("Session channel_id doesn't match: %u != %u\n", be32toh(new_session_data->channel_id), channel_id);
            count_p_dec_err += 1;
            return;
        }

        if (new_session_data->fec_type != WFB_FEC_VDM_RS)
        {
            WFB_ERR("Unsupported FEC codec type: %d\n", new_session_data->fec_type);
            count_p_dec_err += 1;
            return;
        }

        if (new_session_data->n < 1)
        {
            WFB_ERR("Invalid FEC N: %d\n", new_session_data->n);
            count_p_dec_err += 1;
            return;
        }

        if (new_session_data->k < 1 || new_session_data->k > new_session_data->n)
        {
            WFB_ERR("Invalid FEC K: %d\n", new_session_data->k);
            count_p_dec_err += 1;
            return;
        }

        count_p_dec_ok += 1;
        log_rssi(sockaddr, wlan_idx, antenna, rssi, noise, freq, mcs_index, bandwidth);

        if (memcmp(session_key, new_session_data->session_key, sizeof(session_key)) != 0)
        {
            epoch = be64toh(new_session_data->epoch);
            memcpy(session_key, new_session_data->session_key, sizeof(session_key));

            if (fec_p != NULL)
            {
                deinit_fec();
            }

            init_fec(new_session_data->k, new_session_data->n);

            IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d\n", get_time_ms(), epoch, WFB_FEC_VDM_RS, fec_k, fec_n);
            IPC_MSG_SEND();
        }

        return;

    default:
        WFB_ERR("Unknown packet type 0x%x\n", buf[0]);
        count_p_bad += 1;
        return;
    }

    uint8_t decrypted[MAX_FEC_PAYLOAD];
    unsigned long long decrypted_len;
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)buf;

    if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                             NULL,
                                             buf + sizeof(wblock_hdr_t), size - sizeof(wblock_hdr_t),
                                             buf,
                                             sizeof(wblock_hdr_t),
                                             (uint8_t*)(&(block_hdr->data_nonce)), session_key) != 0)
    {
        WFB_ERR("Unable to decrypt packet #0x%" PRIx64 "\n", be64toh(block_hdr->data_nonce));
        count_p_dec_err += 1;
        return;
    }

    count_p_dec_ok += 1;
    log_rssi(sockaddr, wlan_idx, antenna, rssi, noise, freq, mcs_index, bandwidth);

    assert(decrypted_len >= sizeof(wpacket_hdr_t));
    assert(decrypted_len <= MAX_FEC_PAYLOAD);

    uint64_t block_idx = be64toh(block_hdr->data_nonce) >> 8;
    uint8_t fragment_idx = (uint8_t)(be64toh(block_hdr->data_nonce) & 0xff);

    // Should never happend due to generating new session key on tx side
    if (block_idx > MAX_BLOCK_IDX)
    {
        WFB_ERR("block_idx overflow\n");
        count_p_bad += 1;
        return;
    }

    if (fragment_idx >= fec_n)
    {
        WFB_ERR("Invalid fragment_idx: %d\n", fragment_idx);
        count_p_bad += 1;
        return;
    }

    int ring_idx = get_block_ring_idx(block_idx);

    //ignore already processed blocks
    if (ring_idx < 0) return;

    rx_ring_item_t *p = &rx_ring[ring_idx];

    //ignore already processed fragments
    if (p->fragment_map[fragment_idx]) return;

    memset(p->fragments[fragment_idx], '\0', MAX_FEC_PAYLOAD);
    memcpy(p->fragments[fragment_idx], decrypted, decrypted_len);

    p->fragment_map[fragment_idx] = decrypted_len;
    p->has_fragments += 1;

    // Check if we use current (oldest) block
    // then we can optimize and don't wait for all K fragments
    // and send packets if there are no gaps in fragments from the beginning of this block
    if(ring_idx == rx_ring_front)
    {
        // check if there are any packets without gaps
        // and send them immediately
        while(p->fragment_to_send_idx < fec_k && p->fragment_map[p->fragment_to_send_idx])
        {
            send_packet(ring_idx, p->fragment_to_send_idx);
            p->fragment_to_send_idx += 1;
        }

        // remove block if all K elements (without gaps) were sent
        if(p->fragment_to_send_idx == fec_k)
        {
            rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
            rx_ring_alloc -= 1;
            assert(rx_ring_alloc >= 0);
            return;
        }
    }

    // Check that this block has K elements (with gaps) and can be recovered via FEC
    if(p->fragment_to_send_idx < fec_k && p->has_fragments == fec_k)
    {
        // send all queued packets in all unfinished blocks before current
        // and then remove that blocks
        int nrm = modN(ring_idx - rx_ring_front, RX_RING_SIZE);

        while(nrm > 0)
        {
            for(int f_idx=rx_ring[rx_ring_front].fragment_to_send_idx; f_idx < fec_k; f_idx++)
            {
                if(rx_ring[rx_ring_front].fragment_map[f_idx])
                {
                    send_packet(rx_ring_front, f_idx);
                }
            }
            rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
            rx_ring_alloc -= 1;
            nrm -= 1;
        }

        assert(rx_ring_alloc > 0);
        assert(ring_idx == rx_ring_front);

        // Search for missed data fragments and apply FEC only if needed
        for(int f_idx=p->fragment_to_send_idx; f_idx < fec_k; f_idx++)
        {
            if(! p->fragment_map[f_idx])
            {
                uint32_t fec_count = 0;

                //Recover missed fragments using FEC
                apply_fec(ring_idx);

                // Count total number of recovered fragments
                for(; f_idx < fec_k; f_idx++)
                {
                    if(! p->fragment_map[f_idx])
                    {
                        fec_count += 1;
                    }
                }

                if(fec_count)
                {
                    count_p_fec_recovered += fec_count;
                    WFB_DBG("FEC recovered %d packets\n", fec_count);
                }
                break;
            }
        }

        while(p->fragment_to_send_idx < fec_k)
        {
            send_packet(ring_idx, p->fragment_to_send_idx);
            p->fragment_to_send_idx += 1;
        }

        // remove block
        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        rx_ring_alloc -= 1;
        assert(rx_ring_alloc >= 0);
    }
}

void Aggregator::send_packet(int ring_idx, int fragment_idx)
{
    wpacket_hdr_t* packet_hdr = (wpacket_hdr_t*)(rx_ring[ring_idx].fragments[fragment_idx]);
    uint8_t *payload = (rx_ring[ring_idx].fragments[fragment_idx]) + sizeof(wpacket_hdr_t);
    uint8_t flags = packet_hdr->flags;
    uint16_t packet_size = be16toh(packet_hdr->packet_size);
    uint32_t packet_seq = rx_ring[ring_idx].block_idx * fec_k + fragment_idx;

    if (packet_seq > seq + 1 && seq > 0)
    {
        ANDROID_IPC_MSG("PKT_LOST\t%d", (packet_seq - seq - 1));
        count_p_lost += (packet_seq - seq - 1);
    }

    seq = packet_seq;

    if(packet_size > MAX_PAYLOAD_SIZE)
    {
        WFB_ERR("Corrupted packet %u\n", seq);
        count_p_bad += 1;
    }
    else if(!(flags & WFB_PACKET_FEC_ONLY))
    {
        if (callback)
        {
            assert(sockfd == -1);
            (*callback)(payload, packet_size);
        }
        else
        {
            assert(sockfd >= 0);
            sendto(sockfd, payload, packet_size, MSG_DONTWAIT, (sockaddr*)&saddr, sizeof(saddr));
        }
        count_p_outgoing += 1;
        count_b_outgoing += packet_size;
    }
}

void Aggregator::apply_fec(int ring_idx)
{
    assert(fec_k >= 1);
    assert(fec_n >= 1);
    assert(fec_k <= fec_n);
    assert(fec_p != NULL);

    unsigned index[fec_k];
    uint8_t *in_blocks[fec_k];
    uint8_t *out_blocks[fec_n - fec_k];
    int j = fec_k;
    int ob_idx = 0;
    size_t max_packet_size = 0;

    for(int i=0; i < fec_k; i++)
    {
        if(rx_ring[ring_idx].fragment_map[i])
        {
            in_blocks[i] = rx_ring[ring_idx].fragments[i];
            index[i] = i;
        }
        else
        {
            while(j < fec_n && ! rx_ring[ring_idx].fragment_map[j])
            {
                j++;
            }

            assert(j < fec_n);
            // FEC packets always have max size between packets in block
            max_packet_size = max(max_packet_size, rx_ring[ring_idx].fragment_map[j]);
            in_blocks[i] = rx_ring[ring_idx].fragments[j];
            out_blocks[ob_idx++] = rx_ring[ring_idx].fragments[i];
            index[i] = j++;
        }
    }

    assert(max_packet_size > 0);
    assert(max_packet_size <= MAX_FEC_PAYLOAD);
    fec_decode(fec_p, (const uint8_t**)in_blocks, out_blocks, index, max_packet_size);
}


void radio_loop(int argc, char* const *argv, int optind, uint32_t channel_id, unique_ptr<BaseAggregator> &agg, int log_interval, int rcv_buf_size)
{
    int nfds = argc - optind;
    uint64_t log_send_ts = get_time_ms();
    struct pollfd fds[MAX_RX_INTERFACES];
    unique_ptr<Receiver> rx[MAX_RX_INTERFACES];

    if (nfds > MAX_RX_INTERFACES)
    {
        throw runtime_error(string_format("Too many wifi adapters, increase MAX_RX_INTERFACES"));
    }

    memset(fds, '\0', sizeof(fds));

    for(int i = 0; i < nfds; i++)
    {
        rx[i].reset(new Receiver(argv[optind + i], i, channel_id, agg.get(), rcv_buf_size));
        fds[i].fd = rx[i]->getfd();
        fds[i].events = POLLIN;
    }

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int rc = poll(fds, nfds, log_send_ts > cur_ts ? log_send_ts - cur_ts : 0);

        if (rc < 0){
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("Poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();
        if (cur_ts >= log_send_ts)
        {
            agg->dump_stats();
            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        if (rc == 0) continue; // timeout expired

        for(int i = 0; rc > 0 && i < nfds; i++)
        {
            if (fds[i].revents & (POLLERR|POLLNVAL))
            {
                throw runtime_error("socket error!");
            }
            if (fds[i].revents & POLLIN){
                rx[i]->loop_iter();
                rc -= 1;
            }
        }
    }
}

void network_loop(int srv_port, Aggregator &agg, int log_interval, int rcv_buf_size)
{
    wrxfwd_t fwd_hdr;
    struct sockaddr_in sockaddr;
    uint8_t buf[MAX_FORWARDER_PACKET_SIZE];

    uint64_t log_send_ts = get_time_ms();
    struct pollfd fds[1];
    int fd = open_udp_socket_for_rx(srv_port, rcv_buf_size);

    memset(fds, '\0', sizeof(fds));
    fds[0].fd = fd;
    fds[0].events = POLLIN;

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int rc = poll(fds, 1, log_send_ts > cur_ts ? log_send_ts - cur_ts : 0);

        if (rc < 0){
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();
        if (cur_ts >= log_send_ts)
        {
            agg.dump_stats();
            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        if (rc == 0) continue; // timeout expired

        // some events detected
        if (fds[0].revents & (POLLERR | POLLNVAL))
        {
            throw runtime_error(string_format("socket error: %s", strerror(errno)));
        }

        if (fds[0].revents & POLLIN)
        {
            for(;;) // process pending rx
            {
                memset((void*)&sockaddr, '\0', sizeof(sockaddr));

                struct iovec iov[2] = {{ .iov_base = (void*)&fwd_hdr,
                                         .iov_len = sizeof(fwd_hdr)},
                                       { .iov_base = (void*)buf,
                                         .iov_len = sizeof(buf) }};

                struct msghdr msghdr = { .msg_name = (void*)&sockaddr,
                                         .msg_namelen = sizeof(sockaddr),
                                         .msg_iov = iov,
                                         .msg_iovlen = 2,
                                         .msg_control = NULL,
                                         .msg_controllen = 0,
                                         .msg_flags = 0};

                ssize_t rsize = recvmsg(fd, &msghdr, MSG_DONTWAIT);
                if (rsize < 0)
                {
                    break;
                }

                if (rsize < (ssize_t)sizeof(wrxfwd_t))
                {
                    continue;
                }
                agg.process_packet(buf, rsize - sizeof(wrxfwd_t),
                                   fwd_hdr.wlan_idx, fwd_hdr.antenna,
                                   fwd_hdr.rssi, fwd_hdr.noise, ntohs(fwd_hdr.freq),
                                   fwd_hdr.mcs_index, fwd_hdr.bandwidth, &sockaddr);
            }
            if(errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
        }
    }
}

#ifndef __WFB_RX_SHARED_LIBRARY__

int main(int argc, char* const *argv)
{
    int opt;
    uint8_t radio_port = 0;
    uint32_t link_id = 0;
    uint64_t epoch = 0;
    int log_interval = 1000;
    int client_port = 5600;
    int srv_port = 0;
    string client_addr = "127.0.0.1";
    rx_mode_t rx_mode = LOCAL;
    int rcv_buf = 0;

    string keypair = "rx.key";

    while ((opt = getopt(argc, argv, "K:fa:c:u:p:l:i:e:R:")) != -1) {
        switch (opt) {
        case 'K':
            keypair = optarg;
            break;
        case 'f':
            rx_mode = FORWARDER;
            break;
        case 'a':
            rx_mode = AGGREGATOR;
            srv_port = atoi(optarg);
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
        case 'R':
            rcv_buf = atoi(optarg);
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
        default: /* '?' */
        show_usage:
            WFB_INFO("Local receiver: %s [-K rx_key] [-c client_addr] [-u client_port] [-p radio_port] [-R rcv_buf] [-l log_interval] [-e epoch] [-i link_id] interface1 [interface2] ...\n", argv[0]);
            WFB_INFO("Remote (forwarder): %s -f [-c client_addr] [-u client_port] [-p radio_port]  [-R rcv_buf] [-i link_id] interface1 [interface2] ...\n", argv[0]);
            WFB_INFO("Remote (aggregator): %s -a server_port [-K rx_key] [-c client_addr] [-R rcv_buf] [-u client_port] [-l log_interval] [-p radio_port] [-e epoch] [-i link_id]\n", argv[0]);
            WFB_INFO("Default: K='%s', connect=%s:%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", log_interval=%d, rcv_buf=system_default\n", keypair.c_str(), client_addr.c_str(), client_port, link_id, radio_port, epoch, log_interval);
            WFB_INFO("WFB-ng version %s\n", WFB_VERSION);
            WFB_INFO("WFB-ng home page: <http://wfb-ng.org>\n");
            exit(1);
        }
    }

    {
        int fd;
        int c;

        if ((fd = open("/dev/random", O_RDONLY)) != -1) {
            if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
                WFB_ERR("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                        "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                        "On virtualized Linux environments, also consider using virtio-rng.\n"
                        "The service will not start until enough entropy has been collected.\n");
            }
            (void) close(fd);
        }
    }

    if (sodium_init() < 0)
    {
        WFB_ERR("Libsodium init failed\n");
        return 1;
    }

    try
    {
        uint32_t channel_id = (link_id << 8) + radio_port;
        if (rx_mode == LOCAL || rx_mode == FORWARDER)
        {
            if (optind >= argc) goto show_usage;

            unique_ptr<BaseAggregator> agg;
            if(rx_mode == LOCAL){
                agg = unique_ptr<Aggregator>(new Aggregator(client_addr, client_port, keypair, epoch, channel_id));
            }else{
                agg = unique_ptr<Forwarder>(new Forwarder(client_addr, client_port));
            }

            radio_loop(argc, argv, optind, channel_id, agg, log_interval, rcv_buf);
        }else if(rx_mode == AGGREGATOR)
        {
            if (optind > argc) goto show_usage;
            Aggregator agg(client_addr, client_port, keypair, epoch, channel_id);

            network_loop(srv_port, agg, log_interval, rcv_buf);
        }else{
            throw runtime_error(string_format("Unknown rx_mode=%d", rx_mode));
        }
    }catch(runtime_error &e)
    {
        WFB_ERR("Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}

#endif
