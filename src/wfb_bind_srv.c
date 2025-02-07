#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <port> <address> <command> [args...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    int sock_fd, conn_fd;
    struct sockaddr_in server_addr, peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(argv[2]);
    server_addr.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(sock_fd, 1) < 0)
    {
        perror("listen failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Waiting connection on %s:%d\n", argv[2], port);

    if ((conn_fd = accept(sock_fd, (struct sockaddr *)&peer_addr, &peer_addr_len)) < 0)
    {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Connection accepted\n");

    close(sock_fd);
    dup2(conn_fd, STDIN_FILENO);
    dup2(conn_fd, STDOUT_FILENO);
    close(conn_fd);

    execvp(argv[3], argv + 3);

    printf("ERR\tInternal error\n");
    fflush(stdout);
    perror("execvp failed");
    exit(EXIT_FAILURE);
}
