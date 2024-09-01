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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include "tx_cmd.h"

#define COMMAND_TIMEOUT  3  //[seconds]

void alarm_handler(int signum)
{
    char *msg = "Command timed out!\n";
    // printf is not signal safe
    write(2, msg, strlen(msg));
    _exit(1);
}

int send_command(int port, cmd_req_t req, size_t req_size, cmd_resp_t *resp)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    size_t resp_payload_size = 0;

    if (fd < 0)
    {
        perror("socket");
        return 1;
    }

    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1

    // Exit with error code in case of any timeout
    alarm(COMMAND_TIMEOUT);

    int psize = sendto(fd, &req, req_size, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (psize < 0)
    {
        perror("sendto");
        return 1;
    }

    memset(resp, '\0', sizeof(cmd_resp_t));

    psize = recv(fd, resp, sizeof(cmd_resp_t), 0);
    if (psize < 0)
    {
        perror("recvfrom");
        return 1;
    }

    switch(req.cmd_id)
    {
    case CMD_SET_FEC:
    case CMD_SET_RADIO:
        resp_payload_size = 0;
        break;

    case CMD_GET_FEC:
        resp_payload_size = sizeof(resp->u.cmd_get_fec);
        break;

    case CMD_GET_RADIO:
        resp_payload_size = sizeof(resp->u.cmd_get_radio);
        break;

    default:
        assert(0);
    }

    if(psize < offsetof(cmd_resp_t, u) || resp->req_id != req.req_id)
    {
        fprintf(stderr, "Invalid response\n");
        return 1;
    }

    int res = ntohl(resp->rc);

    if(res != 0)
    {
        fprintf(stderr, "Command failed: %s\n", strerror(res));
        return 1;
    }

    if(psize != offsetof(cmd_resp_t, u) + resp_payload_size)
    {
        fprintf(stderr, "Invalid response\n");
        return 1;
    }

    return 0;
}


int set_fec(char *progname, int port, int argc, char **argv)
{
    int opt;
    uint8_t k=8, n=12;
    cmd_req_t req = { .req_id = htonl(rand()), .cmd_id = CMD_SET_FEC };
    cmd_resp_t resp;

    while ((opt = getopt(argc, argv, "k:n:h")) != -1)
    {
        switch (opt)
        {
        case 'k':
            k = atoi(optarg);
            break;

        case 'n':
            n = atoi(optarg);
            break;

        default: /* '?' */
            fprintf(stderr, "Usage: %s <port> %s [-k RS_K] [-n RS_N]\n", progname, argv[0]);
            fprintf(stderr, "Default: k=%d, n=%d\n", k, n);
            fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
            fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
            return 1;
        }
    }

    req.u.cmd_set_fec.k = k;
    req.u.cmd_set_fec.n = n;

    return send_command(port, req, offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_fec), &resp);
}

int set_radio(char *progname, int port, int argc, char **argv)
{
    int opt;
    int bandwidth = 20;
    int short_gi = 0;
    int stbc = 0;
    int ldpc = 0;
    int mcs_index = 1;
    int vht_nss = 1;
    bool vht_mode = false;
    cmd_req_t req = { .req_id = htonl(rand()), .cmd_id = CMD_SET_RADIO };
    cmd_resp_t resp;

    while ((opt = getopt(argc, argv, "B:G:S:L:M:N:Vh")) != -1)
    {
        switch (opt)
        {
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

        case 'V':
            vht_mode = true;
            break;

        default: /* '?' */
            fprintf(stderr, "Usage: %s <port> %s [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-N VHT_NSS] [-V]\n",
                    progname, argv[0]);
            fprintf(stderr, "Default: bandwidth=%d, guard_interval=%s, stbc=%d, ldpc=%d, mcs_index=%d, vht_nss=%d, vht_mode=%d\n",
                    bandwidth, short_gi ? "short" : "long", stbc, ldpc, mcs_index, vht_nss, vht_mode);
            fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
            fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
            return 1;
        }
    }

    req.u.cmd_set_radio.stbc = stbc;
    req.u.cmd_set_radio.ldpc = ldpc;
    req.u.cmd_set_radio.short_gi = short_gi;
    req.u.cmd_set_radio.bandwidth = bandwidth;
    req.u.cmd_set_radio.mcs_index = mcs_index;
    req.u.cmd_set_radio.vht_mode = vht_mode;
    req.u.cmd_set_radio.vht_nss = vht_nss;

    return send_command(port, req, offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_radio), &resp);
}

int get_fec(char *progname, int port, int argc, char **argv)
{
    cmd_req_t req = { .req_id = htonl(rand()), .cmd_id = CMD_GET_FEC };
    cmd_resp_t resp;

    int rc = send_command(port, req, offsetof(cmd_req_t, u), &resp);

    if (rc == 0)
    {
        printf("k=%d\n"
               "n=%d\n",
               resp.u.cmd_get_fec.k,
               resp.u.cmd_get_fec.n);
    }

    return rc;
}

int get_radio(char *progname, int port, int argc, char **argv)
{
    cmd_req_t req = { .req_id = htonl(rand()), .cmd_id = CMD_GET_RADIO };
    cmd_resp_t resp;

    int rc = send_command(port, req, offsetof(cmd_req_t, u), &resp);

    if (rc == 0)
    {
        printf("stbc=%d\n"
               "ldpc=%d\n"
               "short_gi=%d\n"
               "bandwidth=%d\n"
               "mcs_index=%d\n"
               "vht_mode=%d\n"
               "vht_nss=%d\n",
               resp.u.cmd_get_radio.stbc,
               resp.u.cmd_get_radio.ldpc,
               resp.u.cmd_get_radio.short_gi,
               resp.u.cmd_get_radio.bandwidth,
               resp.u.cmd_get_radio.mcs_index,
               resp.u.cmd_get_radio.vht_mode,
               resp.u.cmd_get_radio.vht_nss);
    }
    return rc;
}


int main(int argc, char **argv)
{
    int port;
    char *command;

    struct sigaction act = { 0 };
    act.sa_handler = &alarm_handler;

    if (sigaction(SIGALRM, &act, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <port> {set_fec | set_radio | get_fec | get_radio } ...\n", argv[0]);
        fprintf(stderr, "WFB-ng version %s\n", WFB_VERSION);
        fprintf(stderr, "WFB-ng home page: <http://wfb-ng.org>\n");
        return 1;
    }

    srand(time(NULL));
    port = atoi(argv[1]);
    command = argv[2];

    if (strcmp(command, "set_fec") == 0)
    {
        return set_fec(argv[0], port, argc - 2, argv + 2);
    }
    else if (strcmp(command, "set_radio") == 0)
    {
        return set_radio(argv[0], port, argc - 2, argv + 2);
    }
    else if (strcmp(command, "get_fec") == 0)
    {
        return get_fec(argv[0], port, argc - 2, argv + 2);
    }
    else if (strcmp(command, "get_radio") == 0)
    {
        return get_radio(argv[0], port, argc - 2, argv + 2);
    }
    else
    {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }
}


