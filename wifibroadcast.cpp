// -*- C++ -*-
//
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <memory>

#include "wifibroadcast.hpp"

int open_udp_socket_for_rx(int port)
{
    struct sockaddr_in saddr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) throw runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

    bzero((char *) &saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        throw runtime_error(string_format("Bind error: %s", strerror(errno)));
    }
    return fd;
}
