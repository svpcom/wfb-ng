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


typedef enum {
    LOCAL,
    FORWARDER,
    AGGREGATOR
} rx_mode_t;

class Aggregator
{
public:
    virtual void process_packet(const uint8_t *buf, size_t size) = 0;

protected:
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
};


class RemoteAggregator : public Aggregator
{
public:
    RemoteAggregator(const string &client_addr, int client_port);
    ~RemoteAggregator();
    virtual void process_packet(const uint8_t *buf, size_t size);

private:
    int sockfd;
};


typedef struct {
    uint8_t block_idx;
    uint8_t** fragments;
    uint8_t *fragment_map;
    uint8_t send_fragment_idx;
    uint8_t has_fragments;
} rx_ring_item_t;


#define RX_RING_SIZE 4
#define PROC_RING_SIZE 4

static inline int modN(int x, int base)
{
    return (base + (x % base)) % base;
}

class LocalAggregator : public Aggregator
{
public:
    LocalAggregator(const string &client_addr, int client_port, int k, int n);
    ~LocalAggregator();
    virtual void process_packet(const uint8_t *buf, size_t size);
private:
    void send_packet(int ring_idx, int fragment_idx);
    void apply_fec(int ring_idx);
    int get_block_ring_idx(int block_idx);
    void add_processed_block(int block_idx);
    int rx_ring_push(void);
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    int sockfd;
    uint32_t seq;
    rx_ring_item_t rx_ring[RX_RING_SIZE];
    int rx_ring_front; // current packet
    int rx_ring_alloc; // number of allocated entries
    int proc_ring[PROC_RING_SIZE];
    int proc_ring_last; // index to add processed packet
};

class Receiver
{
public:
    Receiver(const char* wlan, int port, Aggregator* agg);
    ~Receiver();
    void loop_iter(void);
    int getfd(void){ return fd; }
private:
    Aggregator *agg;
    int fd;
    pcap_t *ppcap;
};
