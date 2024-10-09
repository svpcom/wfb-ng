// Copyright (C) 2024 Vasily Evseenko <svpcom@p2ptech.org>

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


#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <event.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// Must be equal to common.radio_mtu !
#define MTU 1445
#define PING_INTERVAL_MS 500

static struct event_base *ev_base;
static struct event *ev_ping;
static struct event *ev_tun_read;
static struct event *ev_tun_read_timeout;
static struct event *ev_tun_write;
static struct event *ev_socket_write;
static struct event *ev_socket_read;

struct sockaddr_in peer_addr;

static int pkt_sem = 0;
static unsigned int agg_timeout_ms = 5;

typedef struct
{
    char data[MTU * 2];
    size_t data_size;  // size of packet buffer
    size_t batch_size; // size of current ready-to-send batch <= MTU
} in_packet_buffer_t;

typedef struct
{
    char data[MTU];
    size_t data_size;  // size of packet buffer
    size_t offset; // offset of current packet for injection into tun
} out_packet_buffer_t;

// TUN packet header
typedef struct {
    uint16_t packet_size;
}  __attribute__ ((packed)) tun_packet_hdr_t;


#ifdef __DEBUG__
#define dbg_log(...)  fprintf(stderr, __VA_ARGS__)
#else
#define dbg_log(...)  ((void)0)
#endif

void event_sig_cb(evutil_socket_t sig, short flags, void *arg)
{
    switch (sig)
    {
    case SIGINT:
    case SIGTERM:
        break;

    default:
        assert(0);
    }

    dbg_log("Exiting...\n");
    event_base_loopexit (ev_base, NULL);
}

void ev_ping_cb(evutil_socket_t fd, short flags, void *arg)
{
    assert(fd >= 0);
    assert((EV_TIMEOUT & flags) != 0);

    if(pkt_sem == 0)
    {
        dbg_log("send ping\n");
        sendto(fd, "", 0, MSG_DONTWAIT, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    }

    if(pkt_sem > 0) pkt_sem--;
}

void ev_tun_read_cb(evutil_socket_t fd, short flags, void *arg)
{
    in_packet_buffer_t *buf = arg;

    assert(buf != NULL);
    assert((EV_TIMEOUT & flags) == 0);
    assert((EV_READ & flags) != 0);
    assert(ev_tun_read != NULL);
    assert(ev_socket_write != NULL);
    assert(buf->data_size < MTU);

    bool is_new_buffer = (buf->data_size == 0);
    int nread = read(fd,
                     buf->data + buf->data_size + sizeof(tun_packet_hdr_t),
                     MTU - sizeof(tun_packet_hdr_t));

    assert(nread > 0);
    assert(nread <= MTU - sizeof(tun_packet_hdr_t));

    ((tun_packet_hdr_t*)(buf->data + buf->data_size))->packet_size = htons(nread);

    buf->data_size += (sizeof(tun_packet_hdr_t) + nread);

    if (buf->data_size <= MTU)
    {
        buf->batch_size = buf->data_size;
    }

    dbg_log("tun_read: packet_size=%d, batch_size=%zu, data_size=%zu\n", nread, buf->batch_size, buf->data_size);

    if(buf->data_size >= MTU || agg_timeout_ms == 0)
    {
        // flush buffer
        event_add(ev_socket_write, NULL);
    }
    else
    {
        // continue aggregation
        event_add(ev_tun_read, NULL);

        if(is_new_buffer && agg_timeout_ms > 0)
        {
            // Set aggregation timeout for new buffer
            struct timeval tv = { .tv_sec = agg_timeout_ms / 1000,
                                  .tv_usec = (agg_timeout_ms % 1000) * 1000 };
            event_add(ev_tun_read_timeout, &tv);
        }

    }
}

void ev_socket_write_cb(evutil_socket_t fd, short flags, void *arg)
{
    in_packet_buffer_t *buf = arg;

    assert(buf != NULL);
    assert(ev_tun_read != NULL);
    assert(ev_socket_write != NULL);

    // reset ping semaphore
    pkt_sem = 1;

    if(flags & EV_WRITE && agg_timeout_ms > 0)
    {
        // reset aggregation timer;
        event_del(ev_tun_read_timeout);
    }

    if(flags & EV_TIMEOUT)
    {
        assert((flags & EV_WRITE) == 0);
        event_del(ev_tun_read);
    }

    assert(buf->batch_size <= MTU);
    sendto(fd, buf->data, buf->batch_size, MSG_DONTWAIT, (struct sockaddr*)&peer_addr, sizeof(peer_addr));

    dbg_log("socket_write: batch_size=%zu, data_size=%zu\n", buf->batch_size, buf->data_size);

    if(buf->data_size > buf->batch_size)
    {
        memmove(buf->data, buf->data + buf->batch_size, buf->data_size - buf->batch_size);
        buf->data_size -= buf->batch_size;
        buf->batch_size = buf->data_size;
    }
    else
    {
        memset(buf, 0, sizeof(in_packet_buffer_t));
    }

    assert(buf->data_size <= MTU);

    if(buf->data_size == MTU || (buf->data_size > 0 && agg_timeout_ms == 0))
    {
        event_add(ev_socket_write, NULL);
    }
    else
    {
        event_add(ev_tun_read, NULL);

        if(buf->data_size > 0 && agg_timeout_ms > 0)
        {
            // Set aggregation timeout for non-empty buffer
            struct timeval tv = { .tv_sec = agg_timeout_ms / 1000,
                                  .tv_usec = (agg_timeout_ms % 1000) * 1000 };

            event_add(ev_tun_read_timeout, &tv);
        }
    }
}


void ev_tun_write_cb(evutil_socket_t fd, short flags, void *arg)
{
    out_packet_buffer_t *buf = arg;
    int nwrote;

    assert(buf != NULL);
    assert((EV_TIMEOUT & flags) == 0);
    assert((EV_WRITE & flags) != 0);
    assert(ev_tun_write != NULL);
    assert(ev_socket_read != NULL);

    assert(buf->offset + sizeof(tun_packet_hdr_t) <= buf->data_size);
    uint16_t packet_size = ntohs(((tun_packet_hdr_t*)(buf->data + buf->offset))->packet_size);

    dbg_log("tun_write: off=%zu, psize=%zu + %d, data_size=%zu\n", buf->offset, sizeof(tun_packet_hdr_t), packet_size, buf->data_size);
    assert(buf->offset + sizeof(tun_packet_hdr_t) + packet_size <= buf->data_size);

    nwrote = write(fd, buf->data + buf->offset + sizeof(tun_packet_hdr_t), packet_size);
    assert(nwrote == packet_size);

    buf->offset += (sizeof(tun_packet_hdr_t) + packet_size);

    if (buf->offset < buf->data_size)
    {
        event_add(ev_tun_write, NULL);
    }
    else
    {
        memset(buf, 0, sizeof(out_packet_buffer_t));
        event_add(ev_socket_read, NULL);
    }
}


void ev_socket_read_cb(evutil_socket_t fd, short flags, void *arg)
{
    out_packet_buffer_t *buf = arg;
    int nread;

    assert(buf != NULL);
    assert((EV_TIMEOUT & flags) == 0);
    assert((EV_READ & flags) != 0);
    assert(ev_socket_read != NULL);
    assert(ev_tun_write != NULL);

    nread = recv(fd,
                 buf->data,
                 MTU,
                 MSG_DONTWAIT);

    assert(nread >= 0);
    assert(nread <= MTU);

    if(nread == 0)
    {
        // skip ping packet
        event_add (ev_socket_read, NULL);
        dbg_log("got ping\n");
        return;
    }

    buf->offset = 0;
    buf->data_size = nread;

    dbg_log("socket_read: off=%zu, data_size=%zu\n", buf->offset, buf->data_size);

    event_add(ev_tun_write, NULL);
}

static int open_tun(char *dev, char *dev_addr)
{
    struct ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC)) < 0)
    {
        perror("open");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if(dev != NULL)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        perror("ioctl");
        close(fd);
        return err;
    }

    if(dev_addr != NULL)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "ip link set up mtu %zu dev %s", MTU - sizeof(tun_packet_hdr_t), ifr.ifr_name);
        if(system(buf) != 0)
        {
            close(fd);
            return -1;
        }
        snprintf(buf, sizeof(buf), "ip addr add %s dev %s", dev_addr, ifr.ifr_name);
        if(system(buf) != 0)
        {
            close(fd);
            return -1;
        }
    }

    return fd;
}


static int create_udpsock(uint16_t bind_port)
{
    int fd;
    struct sockaddr_in saddr;

    if((fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP)) < 0)
    {
        perror("socket");
        return -1;
    }

    const int optval = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(optval)) !=0)
    {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons((unsigned short)bind_port);

    if(bind(fd, (const struct sockaddr *) &saddr, sizeof (saddr)) < 0)
    {
        perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}


int main (int argc, char *argv[])
{
    struct event_config *ev_cfg = NULL;
    struct event *ev_sigint = NULL;
    struct event *ev_sigterm = NULL;

    struct timeval ping_tv = { .tv_sec = PING_INTERVAL_MS / 1000,
                               .tv_usec = (PING_INTERVAL_MS % 1000) * 1000 };

    int tun_fd = -1;
    int sock_fd = -1;

    // buffer TUN -> socket
    in_packet_buffer_t in_buf;

    // buffer socket -> TUN
    out_packet_buffer_t out_buf;

    uint16_t bind_port = 5800;
    char *tun_name = "wfb-tun";
    char *tun_addr = "10.5.0.2/24";
    int opt;

    memset(&in_buf, 0, sizeof(in_buf));
    memset(&out_buf, 0, sizeof(out_buf));

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1
    peer_addr.sin_port = htons(5801);

    while ((opt = getopt(argc, argv, "t:c:u:l:a:T:h")) != -1)
    {
        switch (opt)
        {
        case 't':
            tun_name = strdup(optarg);
            break;

        case 'a':
            tun_addr = strdup(optarg);
            break;

        case 'T':
            agg_timeout_ms = atoi(optarg);
            break;

        case 'c':
            if(inet_pton(AF_INET, optarg, &peer_addr.sin_addr) != 1)
            {
                perror("invalid address");
                return 1;
            }
            break;

        case 'u':
            peer_addr.sin_port = htons(atoi(optarg));
            break;

        case 'l':
            bind_port = atoi(optarg);
            break;

        default: /* '?' */
            fprintf(stderr, "Usage: %s [-t tun_name] [-a tun_addr] [-c peer_addr] [-u peer_port] [-l listen_port] [-T agg_timeout_ms] \n", argv[0]);
            fprintf(stderr, "Default: tun_name=%s, tun_addr=%s, peer_addr=127.0.0.1, peer_port=5801, listen_port=%d, agg_timeout_ms=%u\n", tun_name, tun_addr, bind_port, agg_timeout_ms);
            fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
            fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
            return 1;
        }
    }

    // initialize libevent

#ifdef __DEBUG__
    event_enable_debug_mode();
#endif

    ev_cfg = event_config_new();
    assert(ev_cfg != NULL);

    event_config_require_features(ev_cfg, EV_FEATURE_FDS);
    event_config_set_flag(ev_cfg, EVENT_BASE_FLAG_PRECISE_TIMER);

    ev_base = event_base_new_with_config(ev_cfg);
    assert(ev_base != NULL);

    // event for catching interrupt signal
    ev_sigint = evsignal_new(ev_base, SIGINT, &event_sig_cb, NULL);
    evsignal_add(ev_sigint, NULL);

    ev_sigterm = evsignal_new(ev_base, SIGTERM, &event_sig_cb, NULL);
    evsignal_add(ev_sigterm, NULL);

    sock_fd = create_udpsock(bind_port);
    assert(sock_fd >= 0);

    tun_fd = open_tun(tun_name, tun_addr);
    assert(tun_fd >= 0);

    ev_ping = event_new(ev_base, sock_fd, EV_PERSIST, &ev_ping_cb, NULL);
    event_add(ev_ping, &ping_tv);

    ev_tun_read = event_new(ev_base,
                            tun_fd,
                            EV_READ,
                            &ev_tun_read_cb, &in_buf);

    ev_tun_read_timeout = event_new(ev_base,
                                    sock_fd,
                                    EV_TIMEOUT,
                                    &ev_socket_write_cb, &in_buf);

    ev_socket_read = event_new(ev_base,
                               sock_fd,
                               EV_READ,
                               &ev_socket_read_cb, &out_buf);

    ev_tun_write = event_new(ev_base,
                             tun_fd,
                             EV_WRITE,
                             &ev_tun_write_cb, &out_buf);

    ev_socket_write = event_new(ev_base,
                                sock_fd,
                                EV_WRITE,
                                &ev_socket_write_cb, &in_buf);

    assert(ev_tun_read != NULL);
    assert(ev_socket_read != NULL);

    event_add(ev_tun_read, NULL);
    event_add(ev_socket_read, NULL);
    event_base_dispatch(ev_base);

    close(sock_fd);
    close(tun_fd);

    if(ev_sigint) event_free(ev_sigint);
    if(ev_sigterm) event_free(ev_sigterm);
    if(ev_tun_read) event_free(ev_tun_read);
    if(ev_tun_read_timeout) event_free(ev_tun_read_timeout);
    if(ev_tun_write) event_free(ev_tun_write);
    if(ev_socket_read) event_free(ev_socket_read);
    if(ev_socket_write) event_free(ev_socket_write);
    if(ev_ping) event_free(ev_ping);

    event_base_free (ev_base);
    event_config_free (ev_cfg);
    libevent_global_shutdown();

    return 0;
}
