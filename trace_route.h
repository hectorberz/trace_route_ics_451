#ifndef TRACE_ROUTE_H
#define TRACE_ROUTE_H

#define ICMP_LEN 28
#define PROT_ICMP 1
#define PAK_SIZE 1028
#define DATALEN 56
#define MAX_LONG __LONG_MAX__;
#define NI_MAXHOST 1025
#define NI_MAXSERV 32

/* If the alarm goes off, set skip to true. */
void handler(int signum);

/* Computes the time in microseconds between two timeval objects. */
void get_time(struct timeval *res, struct timeval *ptr);

typedef struct _trace_route
{
    /* Free the trace_route object. */
    void (*destroy)(struct _trace_route *this);

    /* open sock_fd */
    int (*socket)(struct _trace_route *this);

    /* Get the address info from user input. */
    void (*get_addr_info)(struct _trace_route *this);

    /* Get the hostname and set the sin_family to the correct address type. */
    void (*get_hostname)(struct _trace_route *this);

    /* Add a timeout to the socket and set the ttl. */
    void (*set_sock_opts)(struct _trace_route *this);

    /* Add current time to the send_pac and compute the checksum. */
    void (*prep_send_pak)(struct _trace_route *this);

    /* Record the time and call sendto */
    void (*send)(struct _trace_route *this);

    /**
     * Wait for response.
     * If the reponse type is an echo reply, use the time data from the response.
     * Otherwise use the the timeval obj you set in send.
     */
    void (*recvmsg)(struct _trace_route *this);

    /* Print the results */
    int (*print_tr)(struct _trace_route *this);

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
