
/************************
	 *  trace_route.c
	*/

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
#include "trace_route.h"

static const char *tr_lab = "TRACE ROUTE: ";

static int skip = 0;

/**
 * print host name, ip, and rtt. 
 */
static void pnipt(char *name, char *ipstr, long *ttl)
{
    int i;
    printf("%s (%s)", name, ipstr);

    for (i = 0; i < 3; i++)
    {
        printf("  %ld.%ld ms", ttl[i] / 10, ttl[i] % 10);
        ttl[i] = 0;
    }
    printf("\n");
}

/**
 * If the alarm goes off, set skip to true.
 */
void handler(int signum)
{
    skip = 1;
}

/**
 * Computes the time in microseconds between two timeval objects.
 */
void get_time(struct timeval *res, struct timeval *ptr)
{
    if ((res->tv_usec -= ptr->tv_usec) < 0)
    {
        res->tv_sec--;
        res->tv_usec += 1000000;
    }
    res->tv_sec -= ptr->tv_sec;
}

/**
 * Free the trace_route object.
 */
static void _destroy(trace_route *this)
{
    if (NULL != this)
    {
        free(this);
        this = NULL;
    }
}

/**
 * open sock_fd
 */
static int _socket(trace_route *this)
{
    char str[50];

    if ((this->sock_fd = socket(AF_INET, SOCK_RAW, PROT_ICMP)) < 0)
    {
        if (errno == EPERM)
            sprintf(str, "%s%s", tr_lab, "the use of raw sockets requires root privalges\n");
        else
            sprintf(str, "%s%s", tr_lab, "socket\n");

        perror(str);
        exit(EXIT_FAILURE);
    }

    return 0;
}

/**
 * Get the address info from user input.
 */
static void _get_addr_info(trace_route *this)
{
    struct in_addr addr_h;

    if (getaddrinfo(this->target, NULL, NULL, &this->info_h) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s", tr_lab, "Address info.");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
    this->ip_h = (struct sockaddr_in *)this->info_h->ai_addr;
    addr_h = (struct in_addr)this->ip_h->sin_addr;
    this->hip = inet_ntoa(addr_h);
}

/**
 * Get the hostname and set the sin_family to the correct address type.
 */
static void _get_hostname(trace_route *this)
{
    struct sockaddr_in *to;
    struct hostent *hent;
    char nbuf[64];

    to = (struct sockaddr_in *)&this->who_tp;
    to->sin_family = AF_INET;

    if (!inet_aton(this->target, &to->sin_addr))
    {
        hent = gethostbyname(this->target);
        to->sin_family = hent->h_addrtype;
        if (hent->h_length > (int)sizeof(to->sin_addr))
        {
            hent->h_length = sizeof(to->sin_addr);
        }
        memcpy(&to->sin_addr, hent->h_addr, hent->h_length);
        strncpy(nbuf, hent->h_name, sizeof(nbuf) - 1);
        this->hostname = nbuf;
    }
    else
        this->hostname = this->target;

    if (to->sin_family == AF_INET)
        printf("trace route to %s (%s), %d hops max, %d byte packets\n",
               this->hostname, inet_ntoa(to->sin_addr), this->ttl_max, DATALEN + 8);
    else
        printf("trace route to %s, %d hops max, %d byte packets\n",
               this->hostname, this->ttl_max, DATALEN + 8);

    this->hosts_ip = strdup(inet_ntoa(to->sin_addr));
}

/**
 * Add a timeout to the socket and set the ttl.
 */
static void _set_sock_opts(trace_route *this)
{

    if (setsockopt(this->sock_fd, SOL_SOCKET, SO_RCVTIMEO,
                   &this->time_out, sizeof(struct timeval)) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "Set Socket Options Timeval");
        perror(str_err);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(this->sock_fd, IPPROTO_IP, IP_TTL,
                   &this->ttl_cur, sizeof(this->ttl_cur)) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "Set Socket Options TTL");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
}
/**
 * Add current time to the send_pac and compute the checksum.
 */
static void _prep_send_pak(trace_route *this)
{
    gettimeofday((struct timeval *)&this->send_pac[8], (struct timezone *)NULL);

    this->icmp = (struct icmp *)this->send_pac;
    this->icmp->icmp_type = ICMP_ECHO;
    this->icmp->icmp_code = 0;

    this->icmp->icmp_id = this->id;
    this->icmp->icmp_seq = 0;
    this->icmp->icmp_cksum = 0;
    this->packet_len = DATALEN + 8;
    this->icmp->icmp_cksum = checksum((unsigned short *)this->icmp, this->packet_len);
}

/**
 * Record the time and call sendto
 */
static void _send(trace_route *this)
{
    gettimeofday(&this->time_strt, (struct timezone *)NULL);

    if (sendto(this->sock_fd, this->send_pac, this->packet_len, 0,
               (struct sockaddr *)&this->who_tp, sizeof(struct sockaddr)) < 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "Send to");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
}

/**
 * Wait for response.
 * If the reponse type is an echo reply, use the time data from the response.
 * Otherwise use the the timeval obj you set in send.
 */
static void _recvmsg(trace_route *this)
{
    long rtt = 0;
    struct timeval *time_ptr;
    this->iov.iov_base = this->recv_pac;
    this->iov.iov_len = PAK_SIZE;

    this->msg.msg_name = NULL;
    this->msg.msg_namelen = 0;
    this->msg.msg_iov = &this->iov;
    this->msg.msg_iovlen = 1;
    this->msg.msg_control = this->cont_pac;
    this->msg.msg_controllen = PAK_SIZE;

    if ((this->recv_len = recvmsg(this->sock_fd, &this->msg, 0)) < 0)
    {
        skip = 1;
    }
    gettimeofday(&this->time_fin, (struct timezone *)NULL);

    this->ip_out = (struct ip *)this->recv_pac;
    this->ip_len = this->ip_out->ip_hl << 2;
    this->recv_len -= this->ip_len;
    this->icmp = (struct icmp *)(this->recv_pac + this->ip_len);
    this->ip_in = inet_ntoa(this->ip_out->ip_src);

    if (this->icmp->icmp_type == ICMP_ECHOREPLY)
        time_ptr = (struct timeval *)this->icmp->icmp_data;

    else if (this->icmp->icmp_type == ICMP_TIME_EXCEEDED)
        time_ptr = (struct timeval *)&this->time_strt;

    get_time(&this->time_fin, time_ptr);
    rtt = (this->time_fin.tv_sec * 10000 + (this->time_fin.tv_usec / 100));
    this->rtt_s[this->attempt] = rtt;
}

/**
 * Print the results
 */
static int _print_tr(trace_route *this)
{
    char name_h[NI_MAXHOST];
    struct sockaddr_in ip_d;

    ip_d.sin_family = AF_INET;

    if (this->recv_len < 0)
    {
        printf("%2d  * * *\n", this->ttl_cur);
        return 0;
    }
    strcpy(this->ip_last_vst, this->ip_in);

    inet_pton(AF_INET, this->ip_in, &ip_d.sin_addr);

    if (getnameinfo((struct sockaddr *)&ip_d, sizeof(ip_d),
                    name_h, sizeof(name_h), NULL, 0, 0) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "getnameinfo");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
    printf("%2d  ", this->ttl_cur);
    pnipt(name_h, this->ip_in, this->rtt_s);

    if ((strcmp(this->ip_in, this->hosts_ip)) == 0)
        return 1;

    return 0;
}

trace_route *BEGIN_TRACE_ROUTE(char *target, int ttl_max)
{
    trace_route *this = malloc(sizeof(*this));
    this->destroy = _destroy;
    this->get_addr_info = _get_addr_info;
    this->socket = _socket;
    this->set_sock_opts = _set_sock_opts;
    this->prep_send_pak = _prep_send_pak;
    this->send = _send;
    this->recvmsg = _recvmsg;
    this->print_tr = _print_tr;
    this->get_hostname = _get_hostname;

    this->ttl_max = ttl_max;
    this->ttl_beg = 1;
    this->ttl_cur = this->ttl_beg;
    this->target = target;
    this->recv_len = 0;

    this->id = (getpid() & 0xffff);
    return this;
}
int main(int argc, char *argv[])
{
    int fin = 0;
    if (argc < 2)
    {
        char str_err[50];
        sprintf(str_err, "%s%s", tr_lab, "Trace route requires an argument.");
        printf("%s\n", str_err);
        exit(EXIT_FAILURE);
    }

    trace_route *tr = BEGIN_TRACE_ROUTE(argv[1], 30);

    tr->attempt = 0;
    tr->time_out.tv_sec = 0;
    tr->time_out.tv_usec = 500000;

    tr->get_addr_info(tr);
    tr->socket(tr);
    tr->get_hostname(tr);

    while (tr->ttl_cur < tr->ttl_max && !fin)
    {
        skip = 0;
        signal(SIGALRM, handler);
        alarm(3);

        while (tr->attempt < 3 && !skip)
        {
            tr->set_sock_opts(tr);
            tr->prep_send_pak(tr);
            tr->send(tr);
            tr->recvmsg(tr);
            tr->attempt++;
        }
        tr->attempt = 0;
        fin = tr->print_tr(tr);
        tr->ttl_cur++;
    }
    close(tr->sock_fd);
    tr->destroy(tr);
    return 0;
}