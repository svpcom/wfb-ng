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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

class Transmitter
{
public:
    Transmitter(int k, int m, const string &keypair);
    virtual ~Transmitter();
    void send_packet(const uint8_t *buf, size_t size);
    void send_session_key(void);

protected:
    virtual void inject_packet(const uint8_t *buf, size_t size) = 0;

private:
    void send_block_fragment(size_t packet_size);
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint64_t block_idx; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx;
    uint32_t seq;
    uint8_t** block;
    size_t max_packet_size;

    // tx->rx keypair
    uint8_t tx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t rx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];
    wsession_key_t session_key_packet;
};


class PcapTransmitter : public Transmitter
{
public:
    PcapTransmitter(int k, int m, const string &keypair, uint8_t radio_port, const char* wlan);
    virtual ~PcapTransmitter();

private:
    virtual void inject_packet(const uint8_t *buf, size_t size);
    uint8_t radio_port;
    string wlan;
    uint16_t ieee80211_seq;
    pcap_t *ppcap;
};


class UdpTransmitter : public Transmitter
{
public:
    UdpTransmitter(int k, int m, const string &keypair, const string &client_addr, int client_port) : Transmitter(k, m, keypair)
    {
        sockfd = open_udp_socket(client_addr, client_port);
    }

    virtual ~UdpTransmitter()
    {
        close(sockfd);
    }

private:
    virtual void inject_packet(const uint8_t *buf, size_t size)
    {
        send(sockfd, buf, size, 0);
    }

    int open_udp_socket(const string &client_addr, int client_port)
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

    int sockfd;
};
