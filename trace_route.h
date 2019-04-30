#ifndef TRACE_ROUTE_H
#define TRACE_ROUTE_H

#define ICMP_LEN 28
#define PROT_ICMP 1
#define PAK_SIZE 1028
#define DATALEN 56
#define MAX_LONG __LONG_MAX__;
#define NI_MAXHOST 1025
#define NI_MAXSERV 32

void handler(int signum);
void get_time(struct timeval *start, struct timeval *end);

typedef struct _tr
{
    void (*destroy)(struct _tr *this);
    int (*socket)(struct _tr *this);
    void (*get_addr_info)(struct _tr *this);
    void (*get_hostname)(struct _tr *this);
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

    char *hosts_ip;
    long rtt_s[3];

    struct addrinfo *info_h;
    struct sockaddr_in *ip_h;
    struct in_addr addr_h;

    struct sockaddr to;
    struct sockaddr_in who_tp;
    struct icmp *icmp;
    struct iovec iov;
    struct msghdr msg;

    char send_pac[PAK_SIZE], recv_pac[PAK_SIZE], cont_pac[PAK_SIZE];
    char *hip;
    char *hostname;
    int packet_len, recv_len, ip_len;

    int ttl_max, ttl_beg, ttl_cur;
    int id;
    int sock_fd;
    char *target;
    int attempt;

} trace_route;
trace_route *BEGIN_TRACE_ROUTE(char *target, int ttl_max);

#endif /* TRACE_ROUTE_H */
