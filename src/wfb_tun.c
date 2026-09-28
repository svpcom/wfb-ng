// Copyright (C) 2024 - 2026 Vasily Evseenko <svpcom@p2ptech.org>

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
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <event.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// The batch (payload of one frame): -m, radio_mtu of wfb-ng by default,
// MAX_PAYLOAD_SIZE of wifibroadcast.hpp (WIFI_MTU 4045) at most
#define MTU_DEFAULT 1445
#define MTU_MAX 3993
static size_t mtu = MTU_DEFAULT;
#define PING_INTERVAL_MS 500
#define MAX_CTL_PORTS 16

static struct event_base *ev_base;
static struct event *ev_tun_read;
static int tun_fd = -1;

typedef struct
{
    char data[MTU_MAX * 2];
    size_t data_size;  // size of packet buffer
    size_t batch_size; // size of current ready-to-send batch <= mtu
} in_packet_buffer_t;

typedef struct
{
    char data[MTU_MAX];
    size_t data_size;  // size of packet buffer
    size_t offset; // offset of current packet for injection into tun
} out_packet_buffer_t;

// TUN packet header
typedef struct {
    uint16_t packet_size;
}  __attribute__ ((packed)) tun_packet_hdr_t;

// One wfb_tx/wfb_rx pair. The data stream aggregates TUN packets into
// batches, the control stream (babeld, liveness probes) sends every packet
// at once so that it never waits behind data. The pair is reached over UDP
// on localhost or over abstract unix datagram sockets (-U): no IP stack per
// packet, no port to allocate.
typedef struct {
    const char *name;
    int fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
    unsigned int agg_timeout_ms;   // 0: no aggregation
    uint64_t last_push_us;         // the previous packet from the tun
    int pkt_sem;
    struct event *ev_ping;
    struct event *ev_agg_timeout;
    struct event *ev_socket_read;
    struct event *ev_tun_write;
    in_packet_buffer_t in_buf;     // TUN -> socket
    out_packet_buffer_t out_buf;   // socket -> TUN
} stream_t;

static stream_t data_stream = { .name = "data", .fd = -1 };
static stream_t ctl_stream = { .name = "ctl", .fd = -1 };
static uint16_t ctl_ports[MAX_CTL_PORTS];
static int ctl_ports_count = 0;


// Don't use possible C++ loggers
#ifdef WFB_DBG
#undef WFB_DBG
#endif

#ifdef __DEBUG__
#define WFB_DBG(...)  fprintf(stderr, __VA_ARGS__)
#else
#define WFB_DBG(...)  ((void)0)
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

    WFB_DBG("Exiting...\n");
    event_base_loopexit (ev_base, NULL);
}

void ev_ping_cb(evutil_socket_t fd, short flags, void *arg)
{
    stream_t *s = arg;

    assert((EV_TIMEOUT & flags) != 0);

    if(s->pkt_sem == 0)
    {
        WFB_DBG("%s: send ping\n", s->name);
        sendto(s->fd, "", 0, MSG_DONTWAIT, (struct sockaddr*)&s->peer_addr, s->peer_len);
    }

    if(s->pkt_sem > 0) s->pkt_sem--;
}

// UDP destination port of an IPv4/IPv6 packet, 0 for anything else
static uint16_t udp_dst_port(const uint8_t *pkt, size_t len)
{
    size_t off;

    if (len < 1) return 0;

    switch (pkt[0] >> 4)
    {
    case 4:
        off = (pkt[0] & 0x0f) * 4;
        // not UDP or not the first fragment
        if (len < 20 || pkt[9] != IPPROTO_UDP || (((pkt[6] & 0x1f) << 8) | pkt[7]) != 0) return 0;
        break;

    case 6:
        off = 40;
        // extension headers are not walked: babeld and probes have none
        if (len < 40 || pkt[6] != IPPROTO_UDP) return 0;
        break;

    default:
        return 0;
    }

    if (len < off + 4) return 0;
    return (pkt[off + 2] << 8) | pkt[off + 3];
}

static bool is_ctl_packet(const uint8_t *pkt, size_t len)
{
    uint16_t port = udp_dst_port(pkt, len);

    for (int i = 0; port != 0 && i < ctl_ports_count; i++)
    {
        if (ctl_ports[i] == port) return true;
    }
    return false;
}

static void stream_set_agg_timeout(stream_t *s)
{
    struct timeval tv = { .tv_sec = s->agg_timeout_ms / 1000,
                          .tv_usec = (s->agg_timeout_ms % 1000) * 1000 };
    event_add(s->ev_agg_timeout, &tv);
}

// Send the ready batch, keep the packet that did not fit as the next one
static void stream_send_batch(stream_t *s)
{
    in_packet_buffer_t *buf = &s->in_buf;

    assert(buf->batch_size > 0);
    assert(buf->batch_size <= mtu);

    // reset ping semaphore
    s->pkt_sem = 1;

    sendto(s->fd, buf->data, buf->batch_size, MSG_DONTWAIT, (struct sockaddr*)&s->peer_addr, s->peer_len);

    WFB_DBG("%s: socket_write: batch_size=%zu, data_size=%zu\n", s->name, buf->batch_size, buf->data_size);

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

    assert(buf->data_size <= mtu);
}

static uint64_t monotonic_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

// Room for another packet like the last one; without it the batch has
// nothing to wait for: a stream of big packets never aggregates, the
// timeout only delayed every packet by itself
static bool stream_has_room(const stream_t *s, size_t size)
{
    return s->in_buf.data_size + sizeof(tun_packet_hdr_t) + size <= mtu;
}

static void stream_push(stream_t *s, const uint8_t *pkt, size_t size)
{
    in_packet_buffer_t *buf = &s->in_buf;
    bool is_new_buffer = (buf->data_size == 0);
    uint64_t now = monotonic_us();
    // nothing came within the timeout before it: nothing is likely to come
    // within the timeout after it either, the wait only delays it
    bool alone = is_new_buffer && now - s->last_push_us > (uint64_t)s->agg_timeout_ms * 1000;

    s->last_push_us = now;
    assert(buf->data_size < mtu);
    assert(size <= mtu - sizeof(tun_packet_hdr_t));

    ((tun_packet_hdr_t*)(buf->data + buf->data_size))->packet_size = htons(size);
    memcpy(buf->data + buf->data_size + sizeof(tun_packet_hdr_t), pkt, size);
    buf->data_size += (sizeof(tun_packet_hdr_t) + size);

    if (buf->data_size <= mtu)
    {
        buf->batch_size = buf->data_size;
    }

    WFB_DBG("%s: tun_read: packet_size=%zu, batch_size=%zu, data_size=%zu\n", s->name, size, buf->batch_size, buf->data_size);

    if(buf->data_size < mtu && s->agg_timeout_ms > 0 && !alone && stream_has_room(s, size))
    {
        // continue aggregation
        if(is_new_buffer)
        {
            stream_set_agg_timeout(s);
        }
        return;
    }

    if(s->agg_timeout_ms > 0)
    {
        event_del(s->ev_agg_timeout);
    }

    stream_send_batch(s);

    // the packet that did not fit is the next batch: out at once when
    // nothing more would fit behind it either
    if(buf->data_size > 0 && !stream_has_room(s, size))
    {
        stream_send_batch(s);
    }
    else if(buf->data_size > 0)
    {
        stream_set_agg_timeout(s);
    }
}

void ev_agg_timeout_cb(evutil_socket_t fd, short flags, void *arg)
{
    stream_t *s = arg;

    assert((EV_TIMEOUT & flags) != 0);

    if(s->in_buf.batch_size > 0)
    {
        stream_send_batch(s);
    }

    if(s->in_buf.data_size > 0)
    {
        stream_set_agg_timeout(s);
    }
}

void ev_tun_read_cb(evutil_socket_t fd, short flags, void *arg)
{
    uint8_t pkt[MTU_MAX];

    assert((EV_READ & flags) != 0);

    int nread = read(fd, pkt, mtu - sizeof(tun_packet_hdr_t));

    if (nread <= 0)
    {
        // No data ready (EAGAIN), interrupted, or EOF: keep listening.
        if (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        {
            fprintf(stderr, "tun read error: %s\n", strerror(errno));
        }
        return;
    }

    if (ctl_stream.fd >= 0 && is_ctl_packet(pkt, nread))
    {
        stream_push(&ctl_stream, pkt, nread);
    }
    else
    {
        stream_push(&data_stream, pkt, nread);
    }
}


void ev_tun_write_cb(evutil_socket_t fd, short flags, void *arg)
{
    stream_t *s = arg;
    out_packet_buffer_t *buf = &s->out_buf;
    int nwrote;

    assert((EV_TIMEOUT & flags) == 0);
    assert((EV_WRITE & flags) != 0);

    if (buf->offset + sizeof(tun_packet_hdr_t) > buf->data_size)
    {
        // Truncated/misframed batch from the peer: drop it and resume reading
        // instead of aborting the tunnel.
        fprintf(stderr, "%s: tun_write: truncated batch header, dropping\n", s->name);
        memset(buf, 0, sizeof(out_packet_buffer_t));
        event_add(s->ev_socket_read, NULL);
        return;
    }

    uint16_t packet_size = ntohs(((tun_packet_hdr_t*)(buf->data + buf->offset))->packet_size);

    WFB_DBG("%s: tun_write: off=%zu, psize=%zu + %d, data_size=%zu\n", s->name, buf->offset, sizeof(tun_packet_hdr_t), packet_size, buf->data_size);

    if (buf->offset + sizeof(tun_packet_hdr_t) + packet_size > buf->data_size)
    {
        // Framed length runs past the received batch: drop and resume reading.
        fprintf(stderr, "%s: tun_write: framed packet_size overruns batch, dropping\n", s->name);
        memset(buf, 0, sizeof(out_packet_buffer_t));
        event_add(s->ev_socket_read, NULL);
        return;
    }

    nwrote = write(fd, buf->data + buf->offset + sizeof(tun_packet_hdr_t), packet_size);

    if (nwrote != (int)packet_size)
    {
        if (nwrote < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        {
            // TUN queue full: retry this same packet once the device is writable
            // again (offset is not advanced).
            event_add(s->ev_tun_write, NULL);
            return;
        }

        // Hard error or short write: drop the rest of the batch and resume reading.
        fprintf(stderr, "%s: tun write error (%d/%u): %s\n", s->name, nwrote, packet_size, strerror(errno));
        memset(buf, 0, sizeof(out_packet_buffer_t));
        event_add(s->ev_socket_read, NULL);
        return;
    }

    buf->offset += (sizeof(tun_packet_hdr_t) + packet_size);

    if (buf->offset < buf->data_size)
    {
        event_add(s->ev_tun_write, NULL);
    }
    else
    {
        memset(buf, 0, sizeof(out_packet_buffer_t));
        event_add(s->ev_socket_read, NULL);
    }
}


void ev_socket_read_cb(evutil_socket_t fd, short flags, void *arg)
{
    stream_t *s = arg;
    out_packet_buffer_t *buf = &s->out_buf;
    int nread;

    assert((EV_TIMEOUT & flags) == 0);
    assert((EV_READ & flags) != 0);

    // the peer's -m, not ours: it may send bigger batches
    nread = recv(fd,
                 buf->data,
                 sizeof(buf->data),
                 MSG_DONTWAIT);

    if (nread < 0)
    {
        // No datagram ready (EAGAIN) or interrupted: keep listening.
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        {
            fprintf(stderr, "%s: socket recv error: %s\n", s->name, strerror(errno));
        }
        event_add(s->ev_socket_read, NULL);
        return;
    }

    if(nread == 0)
    {
        // skip ping packet
        event_add (s->ev_socket_read, NULL);
        WFB_DBG("%s: got ping\n", s->name);
        return;
    }

    buf->offset = 0;
    buf->data_size = nread;

    WFB_DBG("%s: socket_read: off=%zu, data_size=%zu\n", s->name, buf->offset, buf->data_size);

    event_add(s->ev_tun_write, NULL);
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
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
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
        snprintf(buf, sizeof(buf), "ip link set up mtu %zu dev %s", mtu - sizeof(tun_packet_hdr_t), ifr.ifr_name);
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


// Abstract unix socket address "@name": nothing on the filesystem
static socklen_t unix_addr(struct sockaddr_un *sa, const char *name)
{
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    strncpy(sa->sun_path + 1, name, sizeof(sa->sun_path) - 2);
    return sizeof(sa_family_t) + 1 + strlen(sa->sun_path + 1);
}


static int create_unixsock(const char *bind_name)
{
    int fd;
    struct sockaddr_un saddr;
    socklen_t len = unix_addr(&saddr, bind_name);

    if((fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0)
    {
        perror("socket");
        return -1;
    }

    if(bind(fd, (const struct sockaddr *) &saddr, len) < 0)
    {
        perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}


static int stream_start(stream_t *s, int fd, const struct sockaddr *peer, socklen_t peer_len, unsigned int agg_timeout_ms)
{
    struct timeval ping_tv = { .tv_sec = PING_INTERVAL_MS / 1000,
                               .tv_usec = (PING_INTERVAL_MS % 1000) * 1000 };

    if (fd < 0) return -1;
    s->fd = fd;

    memset(&s->peer_addr, 0, sizeof(s->peer_addr));
    memcpy(&s->peer_addr, peer, peer_len);
    s->peer_len = peer_len;
    s->agg_timeout_ms = agg_timeout_ms;

    s->ev_ping = event_new(ev_base, -1, EV_PERSIST, &ev_ping_cb, s);
    s->ev_agg_timeout = event_new(ev_base, -1, EV_TIMEOUT, &ev_agg_timeout_cb, s);
    s->ev_socket_read = event_new(ev_base, s->fd, EV_READ, &ev_socket_read_cb, s);
    s->ev_tun_write = event_new(ev_base, tun_fd, EV_WRITE, &ev_tun_write_cb, s);

    assert(s->ev_ping != NULL);
    assert(s->ev_agg_timeout != NULL);
    assert(s->ev_socket_read != NULL);
    assert(s->ev_tun_write != NULL);

    event_add(s->ev_ping, &ping_tv);
    event_add(s->ev_socket_read, NULL);
    return 0;
}

static int stream_start_udp(stream_t *s, uint16_t bind_port, struct in_addr peer_ip, uint16_t peer_port, unsigned int agg_timeout_ms)
{
    struct sockaddr_in peer;

    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_addr = peer_ip;
    peer.sin_port = htons(peer_port);
    return stream_start(s, create_udpsock(bind_port), (struct sockaddr*)&peer, sizeof(peer), agg_timeout_ms);
}

// The stream listens on "@<prefix>.<stream>.in" (wfb_rx -U sends there) and
// sends to "@<prefix>.<stream>.out" (wfb_tx -U listens there)
static int stream_start_unix(stream_t *s, const char *prefix, unsigned int agg_timeout_ms)
{
    char name[sizeof(((struct sockaddr_un*)0)->sun_path)];
    struct sockaddr_un peer;
    socklen_t len;
    int fd;

    snprintf(name, sizeof(name), "%s.%s.in", prefix, s->name);
    fd = create_unixsock(name);
    snprintf(name, sizeof(name), "%s.%s.out", prefix, s->name);
    len = unix_addr(&peer, name);
    return stream_start(s, fd, (struct sockaddr*)&peer, len, agg_timeout_ms);
}

static void stream_stop(stream_t *s)
{
    if (s->fd < 0) return;
    close(s->fd);
    event_free(s->ev_ping);
    event_free(s->ev_agg_timeout);
    event_free(s->ev_socket_read);
    event_free(s->ev_tun_write);
}

static int parse_ctl_ports(char *list)
{
    for (char *p = strtok(list, ","); p != NULL; p = strtok(NULL, ","))
    {
        int port = atoi(p);
        if (port <= 0 || port > 65535 || ctl_ports_count >= MAX_CTL_PORTS) return -1;
        ctl_ports[ctl_ports_count++] = port;
    }
    return 0;
}


int main (int argc, char *argv[])
{
    struct event_config *ev_cfg = NULL;
    struct event *ev_sigint = NULL;
    struct event *ev_sigterm = NULL;

    uint16_t bind_port = 5800;
    uint16_t peer_port = 5801;
    int ctl_bind_port = 0;
    int ctl_peer_port = 0;
    unsigned int agg_timeout_ms = 5;
    struct in_addr peer_ip = { .s_addr = htonl(0x7f000001) }; // 127.0.0.1
    char *unix_prefix = NULL;
    char *tun_name = "wfb-tun";
    char *tun_addr = "10.5.0.2/24";
    int opt;

    while ((opt = getopt(argc, argv, "t:c:u:l:a:T:C:L:F:U:m:h")) != -1)
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
            if(inet_pton(AF_INET, optarg, &peer_ip) != 1)
            {
                perror("invalid address");
                return 1;
            }
            break;

        case 'u':
            peer_port = atoi(optarg);
            break;

        case 'l':
            bind_port = atoi(optarg);
            break;

        case 'C':
            ctl_peer_port = atoi(optarg);
            break;

        case 'L':
            ctl_bind_port = atoi(optarg);
            break;

        case 'F':
            if (parse_ctl_ports(optarg) < 0)
            {
                fprintf(stderr, "invalid control port list: %s\n", optarg);
                return 1;
            }
            break;

        case 'U':
            unix_prefix = strdup(optarg);
            break;

        case 'm':
            mtu = atoi(optarg);
            if (mtu < 2 * sizeof(tun_packet_hdr_t) + 64 || mtu > MTU_MAX)
            {
                fprintf(stderr, "invalid mtu %s: 68..%d\n", optarg, MTU_MAX);
                return 1;
            }
            break;

        default: /* '?' */
            fprintf(stderr, "Usage: %s [-t tun_name] [-a tun_addr] [-m mtu] [-T agg_timeout_ms] [-F udp_port,...]\n"
                            "          { [-c peer_addr] [-u peer_port] [-l listen_port] [-C ctl_peer_port -L ctl_listen_port] | -U unix_prefix }\n", argv[0]);
            fprintf(stderr, "Default: tun_name=%s, tun_addr=%s, mtu=%d (the batch; the tun gets 2 less), peer_addr=127.0.0.1, peer_port=%d, listen_port=%d, agg_timeout_ms=%u\n", tun_name, tun_addr, MTU_DEFAULT, peer_port, bind_port, agg_timeout_ms);
            fprintf(stderr, "Control stream: packets to the listed UDP destination ports go to ctl_peer_port one by one, without aggregation\n");
            fprintf(stderr, "-U: abstract unix sockets instead of UDP: wfb_rx -U <prefix>.data.in, wfb_tx -U <prefix>.data.out,\n"
                            "    with -F also <prefix>.ctl.in and <prefix>.ctl.out; raise net.unix.max_dgram_qlen (10 by default)\n");
            fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
            fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
            return 1;
        }
    }

    if (unix_prefix == NULL && (ctl_peer_port != 0) != (ctl_bind_port != 0))
    {
        fprintf(stderr, "-C and -L go together\n");
        return 1;
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

    tun_fd = open_tun(tun_name, tun_addr);
    assert(tun_fd >= 0);

    if (unix_prefix != NULL)
    {
        if (stream_start_unix(&data_stream, unix_prefix, agg_timeout_ms) < 0) return 1;
        if (ctl_ports_count > 0 && stream_start_unix(&ctl_stream, unix_prefix, 0) < 0) return 1;
    }
    else
    {
        if (stream_start_udp(&data_stream, bind_port, peer_ip, peer_port, agg_timeout_ms) < 0) return 1;
        if (ctl_peer_port != 0 && stream_start_udp(&ctl_stream, ctl_bind_port, peer_ip, ctl_peer_port, 0) < 0) return 1;
    }

    ev_tun_read = event_new(ev_base, tun_fd, EV_READ | EV_PERSIST, &ev_tun_read_cb, NULL);
    assert(ev_tun_read != NULL);
    event_add(ev_tun_read, NULL);

    event_base_dispatch(ev_base);

    stream_stop(&ctl_stream);
    stream_stop(&data_stream);
    close(tun_fd);

    if(ev_sigint) event_free(ev_sigint);
    if(ev_sigterm) event_free(ev_sigterm);
    if(ev_tun_read) event_free(ev_tun_read);

    event_base_free (ev_base);
    event_config_free (ev_cfg);
    libevent_global_shutdown();

    return 0;
}
