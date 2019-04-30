#ifndef TRACE_ROUTE_H
#define TRACE_ROUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include "checksum.h"

#define ICMP_LEN 28
#define PROT_ICMP 1
#define PAK_SIZE 1024
#define DATALEN 56
#define MAX_LONG __LONG_MAX__;
#define NI_MAXHOST 1025
#define NI_MAXSERV 32

typedef enum
{
    starting,
    sending,
    receiving,
    printing
} tr_states;

typedef int bool_fun(int retval, int deps);

void check_err(bool_fun, const char *message);

typedef struct _tr
{
    void (*destroy)(struct _tr *this);
    int (*socket)(struct _tr *this);
    void (*get_addr_info)(struct _tr *this);
    void (*set_sock_opts)(struct _tr *this);
    void (*prep_send_pak)(struct _tr *this);
    void (*send)(struct _tr *this);
    void (*recvmsg)(struct _tr *this);
    int (*print_tr)(struct _tr *this);
    struct timeval time_strt;
    struct timeval time_fin;
    struct timeval time_out;

    struct ip *ip_out;

    char *ip_in;
    char ip_last_vst[50];
    char ip_dest[50];
    long rtt_s[3];
    struct sockaddr going;
    struct sockaddr comming;
    struct sockaddr_in *go;
    struct sockaddr_in *com;

    struct addrinfo *info_h;
    struct sockaddr_in *ip_h;
    struct in_addr addr_h;

    struct icmp *icmp;
    struct iovec iov;
    struct msghdr msg;

    char send_pac[PAK_SIZE], recv_pac[PAK_SIZE], cont_pac[PAK_SIZE];
    /* host ip */
    char *hip;
    int packet_len, recv_len, ip_len;

    int ttl_max, ttl_beg, ttl_cur;
    int id;
    int sock_fd;
    char *target;
    int attempt;

} trace_route;
typedef void tr_func(struct _tr *this);
trace_route *BEGIN_TRACE_ROUTE(char *target, int ttl_max);
void handler(int signum);
void get_time(struct timeval *start, struct timeval *end);

#endif /* TRACE_ROUTE_H */