#pragma once
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
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>
#include <string>
#include <vector>

#if defined (PREINCLUDE_FILE)
#include PREINCLUDE_FILE
#endif

extern std::string string_format(const char *format, ...);

/* this is the template radiotap header we send packets out with */


#define IEEE80211_RADIOTAP_MCS_HAVE_BW    0x01
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS   0x02
#define IEEE80211_RADIOTAP_MCS_HAVE_GI    0x04
#define IEEE80211_RADIOTAP_MCS_HAVE_FMT   0x08

#define IEEE80211_RADIOTAP_MCS_BW_20    0
#define IEEE80211_RADIOTAP_MCS_BW_40    1
#define IEEE80211_RADIOTAP_MCS_BW_20L   2
#define IEEE80211_RADIOTAP_MCS_BW_20U   3
#define IEEE80211_RADIOTAP_MCS_SGI      0x04
#define IEEE80211_RADIOTAP_MCS_FMT_GF   0x08

#define IEEE80211_RADIOTAP_MCS_HAVE_FEC   0x10
#define IEEE80211_RADIOTAP_MCS_HAVE_STBC  0x20
#define IEEE80211_RADIOTAP_MCS_FEC_LDPC   0x10
#define IEEE80211_RADIOTAP_MCS_STBC_MASK  0x60
#define IEEE80211_RADIOTAP_MCS_STBC_1  1
#define IEEE80211_RADIOTAP_MCS_STBC_2  2
#define IEEE80211_RADIOTAP_MCS_STBC_3  3
#define IEEE80211_RADIOTAP_MCS_STBC_SHIFT 5

#define IEEE80211_RADIOTAP_VHT_FLAG_STBC    0x01
#define IEEE80211_RADIOTAP_VHT_FLAG_SGI     0x04
#define IEEE80211_RADIOTAP_VHT_MCS_MASK     0xF0
#define IEEE80211_RADIOTAP_VHT_NSS_MASK     0x0F
#define IEEE80211_RADIOTAP_VHT_MCS_SHIFT    4
#define IEEE80211_RADIOTAP_VHT_NSS_SHIFT    0
#define IEEE80211_RADIOTAP_VHT_BW_20M       0x00
#define IEEE80211_RADIOTAP_VHT_BW_40M       0x01
#define IEEE80211_RADIOTAP_VHT_BW_80M       0x04
#define IEEE80211_RADIOTAP_VHT_BW_160M      0x0B
#define IEEE80211_RADIOTAP_VHT_CODING_LDPC_USER0    0x01


#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

static const uint8_t radiotap_header_ht[]  __attribute__((unused)) = {
    0x00, 0x00, // <-- radiotap version
    0x0d, 0x00, // <- radiotap header length
    0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
    0x08, 0x00,  // RADIOTAP_F_TX_NOACK
    MCS_KNOWN , 0x00, 0x00 // bitmap, flags, mcs_index
};

static const uint8_t radiotap_header_vht[]  __attribute__((unused)) = {
    0x00, 0x00, // <-- radiotap version
    0x16, 0x00, // <- radiotap header length
    0x00, 0x80, 0x20, 0x00, // <-- radiotap present flags: RADIOTAP_TX_FLAGS + VHT Information
    0x08, 0x00,  // RADIOTAP_F_TX_NOACK
    0x45, 0x00, // Known VHT information: 0000 0000 0100 0101, BW, GI, STBC
    0x00,       // Flags, BIT(0)=STBC, BIT(2)=GI
    0x04,       // BW, 0:20M, 1:40M, 4:80, 11:160
    0x00, 0x00, 0x00, 0x00, // MCS_NSS[0:3]
    0x00,       // Coding[3:0], BCC/LDPC
    0x00,       // Group ID, not used
    0x00, 0x00  // Partial AID, not used
};

#define WIFI_MTU  4045  // Max injected packet size including all wfb-headers.
                        // Please note, that resulting data packet size depends from input UDP packet size
                        // and FEC packet size is max of all UDP packet sizes in this block.
                        // I.e. you can have WIFI_MTU=4045 but if you will not feed large UDP packets
                        // then resulting radio packets will be small.

                        // I've set it to 4045 to allow wfb_rx compatibility with custom wfb_tx builds that can
                        // have maximum allowed mtu value, but I don't recommend to feed UDP packets
                        // larger that 1448 bytes in production.

                        // You can increase it if your card allow larger packets,
                        // but this can lead to interoperability issues and/or kernel crashes.
                        // Use values > 1500 with caution!

                        // If you use non-default MTU then you need to configure proper MTU on WiFi cards manually
                        // (but 8812au and 8812eu drivers set max mtu by default)

                        // Also you may update radio_mtu in master.cfg - set it to not more than MAX_PAYLOAD_SIZE
                        // or see in output of wfb_tx (Radio MTU)

                        // Experemental max allowed WIFI_MTU for: rtl8812au -- 4049, rtl8812eu -- 4045

#define PACKET_INJECTION_TIMEOUT_MS  5

// Radiotap header will be discarded after injection so we can ingnore it in MTU calculations
#define MAX_RX_INTERFACES  8

// offset of MCS_FLAGS and MCS index
#define MCS_FLAGS_OFF 11
#define MCS_IDX_OFF 12

// offset of VHT information
#define VHT_FLAGS_OFF 12
#define VHT_BW_OFF 13
#define VHT_MCSNSS0_OFF 14
#define VHT_CODING_OFF 18

//the last four bytes used for channel_id
#define SRC_MAC_THIRD_BYTE 12
#define DST_MAC_THIRD_BYTE 18
#define FRAME_SEQ_LB 22
#define FRAME_SEQ_HB 23

#define FRAME_TYPE_DATA  0x08
#define FRAME_TYPE_RTS   0xb4

// WFB-NG MAC address format: "W:B:X:X:X:X" where XXXX is channel_id
// channel_id = (link_id << 8) + radio_port
// First address byte 'W'(0x57) has two lower bits set that means that address is multicast and locally administred
// See https://en.wikipedia.org/wiki/MAC_address for reference

static const uint8_t ieee80211_header[] __attribute__((unused)) = {
    0x08, 0x01, 0x00, 0x00,               // data frame, not protected, from STA to DS via an AP, duration not set
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // receiver is broadcast
    0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,   // last four bytes will be replaced by channel_id
    0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,   // last four bytes will be replaced by channel_id
    0x00, 0x00,                           // (seq_num << 4) + fragment_num
};

/*
 WFB-NG protocol:

 radiotap_header:
   ieee_80211_header:
     1. Data packet:
        wblock_hdr_t   { packet_type = 1, nonce = (block_idx << 8) + fragment_idx }
          wpacket_hdr_t  { flags, packet_size }  #
            data                                 #
                                                 +-- encrypted and authenticated by session key
     2. Session packet:
        wsession_hdr_t { packet_type = 2, nonce = random() }
          wsession_data_t { epoch, channel_id,       #
                            fec_type, fec_k, fec_n,  #
                            session_key,             #
                            optional TLV list }      # -- encrypted and signed using rx and tx keys
 */

// data nonce:  56bit block_idx + 8bit fragment_idx
// session nonce: crypto_box_NONCEBYTES of random bytes

#define BLOCK_IDX_MASK ((1LLU << 56) - 1)
#define MAX_BLOCK_IDX ((1LLU << 55) - 1)

// packet types
#define WFB_PACKET_DATA    0x1
#define WFB_PACKET_SESSION 0x2

// FEC types
#define WFB_FEC_VDM_RS  0x1  //Reed-Solomon on Vandermonde matrix

// packet flags
#define WFB_PACKET_FEC_ONLY 0x1

#define SESSION_KEY_ANNOUNCE_MSEC 1000
#define RX_ANT_MAX  4

// Header for forwarding raw packets from RX host to Aggregator in UDP packets
typedef struct {
    uint8_t wlan_idx;
    uint8_t antenna[RX_ANT_MAX]; //RADIOTAP_ANTENNA, list of antenna idx, 0xff for unused slot
    int8_t rssi[RX_ANT_MAX]; //RADIOTAP_DBM_ANTSIGNAL, list of rssi for corresponding antenna idx
    int8_t noise[RX_ANT_MAX]; //RADIOTAP_DBM_ANTNOISE, list of (rssi - snr) for corresponding antenna idx
    uint16_t freq; //IEEE80211_RADIOTAP_CHANNEL -- channel frequency in MHz
    uint8_t mcs_index;
    uint8_t bandwidth;
} __attribute__ ((packed)) wrxfwd_t;

// Network packet headers. All numbers are in network (big endian) format
// Encrypted packets can be either session key or data packet.

// Session key packet

typedef struct {
    uint8_t packet_type;
    uint8_t session_nonce[crypto_box_NONCEBYTES];  // random data
}  __attribute__ ((packed)) wsession_hdr_t;

typedef struct {
    uint64_t epoch; // Drop session packets from old epoch
    uint32_t channel_id; // (link_id << 8) + port_number
    uint8_t fec_type; // Now only supported type is WFB_FEC_VDM_RS
    uint8_t k;   // FEC k
    uint8_t n;   // FEC n
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];
    uint8_t tags[];  // Optional TLV attributes
} __attribute__ ((packed)) wsession_data_t;

// TLV attr header
typedef struct {
    uint8_t id;
    uint16_t len;
    uint8_t value[];
} __attribute__ ((packed)) tlv_hdr_t;

// Data packet. Embed FEC-encoded data

typedef struct {
    uint8_t packet_type;
    uint64_t data_nonce;  // big endian, data_nonce = (block_idx << 8) + fragment_idx
}  __attribute__ ((packed)) wblock_hdr_t;

// Plain data packet after FEC decode

typedef struct {
    uint8_t flags;
    uint16_t packet_size; // big endian
}  __attribute__ ((packed)) wpacket_hdr_t;


#define MAX_PAYLOAD_SIZE (WIFI_MTU - sizeof(ieee80211_header) - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES - sizeof(wpacket_hdr_t))
#define MAX_FEC_PAYLOAD  (WIFI_MTU - sizeof(ieee80211_header) - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES)
#define MAX_FORWARDER_PACKET_SIZE (WIFI_MTU - sizeof(ieee80211_header))
#define MAX_SESSION_PACKET_SIZE (WIFI_MTU - sizeof(ieee80211_header))
#define MIN_DISTRIBUTION_PACKET_SIZE (sizeof(uint32_t) + sizeof(radiotap_header_ht) + sizeof(ieee80211_header))   // ht hdr < vht hdr
#define MAX_DISTRIBUTION_PACKET_SIZE (sizeof(uint32_t) + sizeof(radiotap_header_vht) + WIFI_MTU)
#define MAX_PCAP_PACKET_SIZE (WIFI_MTU + 256)  // radiotap header is variable but 8812au/eu has max rtap buffer size 256

#ifndef WFB_DBG
#ifdef __DEBUG__
#define WFB_DBG(...)  fprintf(stderr, __VA_ARGS__)
#else
#define WFB_DBG(...)  ((void)0)
#endif
#endif

#ifndef WFB_ERR
#define WFB_ERR(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifndef WFB_INFO
#define WFB_INFO(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifndef ANDROID_IPC_MSG
#define ANDROID_IPC_MSG(...) ((void)0)
#endif

#ifndef IPC_MSG
#define IPC_MSG(...) fprintf(stdout, __VA_ARGS__)
#define IPC_MSG_SEND()  fflush(stdout)
#endif

int open_udp_socket_for_rx(int port, int rcv_buf_size, uint32_t bind_addr = INADDR_ANY, int socket_type = SOCK_DGRAM, int socket_protocol = 0);
int open_unix_socket_for_rx(const char *socket_path, int rcv_buf_size, int socket_type = SOCK_DGRAM, int socket_protocol = 0);
uint64_t get_time_ms(void);
uint64_t get_time_us(void);
