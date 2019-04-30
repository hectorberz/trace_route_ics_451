
/************************
	 *  trace_route.c
	*/

#include "trace_route.h"

static const char *tr_lab = "TRACE ROUTE: ";
static int skip = 0;
static void pnip(char *name, char *ipstr, long *ttl)
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
void handler(int signum)
{
    skip = 1;
}
void get_time(struct timeval *res, struct timeval *ptr)
{
    if ((res->tv_usec -= ptr->tv_usec) < 0)
    {
        res->tv_sec--;
        res->tv_usec += 1000000;
    }
    res->tv_sec -= ptr->tv_sec;
}
static void _destroy(trace_route *this)
{
    if (NULL != this)
    {
        free(this);
        this = NULL;
    }
}
/**
 * open the send socket sock_s
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

        printf("trace route to %s (%s), %d hops max, %d byte packets\n", this->hostname, this->hip, this->ttl_max, DATALEN + 8);
}
static void _set_sock_opts(trace_route *this)
{
    this->time_out.tv_sec = 0;
    this->time_out.tv_usec = 500000;

    if (setsockopt(this->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &this->time_out, sizeof(struct timeval)) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "Set Socket Options Timeval");
        perror(str_err);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(this->sock_fd, IPPROTO_IP, IP_TTL, &this->ttl_cur, sizeof(this->ttl_cur)) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "Set Socket Options TTL");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
}

static void _prep_send_pak(trace_route *this)
{

    this->icmp = (struct icmp *)this->send_pac;
    this->icmp->icmp_type = ICMP_ECHO;
    this->icmp->icmp_code = 0;

    this->icmp->icmp_id = this->id;
    this->icmp->icmp_seq = 0;
    this->icmp->icmp_cksum = checksum((unsigned short *)this->icmp, sizeof(struct icmp));
    this->packet_len = DATALEN + 8;
}
static void _send(trace_route *this)
{
    gettimeofday(&this->time_strt, (struct timezone *)NULL);
    if (sendto(this->sock_fd, this->send_pac, this->packet_len, 0, this->info_h->ai_addr, this->info_h->ai_addrlen) == -1)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "Send to");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
}
static void _recvmsg(trace_route *this)
{
    long rtt = 0;
    this->iov.iov_base = this->recv_pac;
    this->iov.iov_len = PAK_SIZE;

    this->msg.msg_name = NULL;
    this->msg.msg_namelen = 0;
    this->msg.msg_iov = &this->iov;
    this->msg.msg_iovlen = 1;
    this->msg.msg_control = this->cont_pac;
    this->msg.msg_controllen = PAK_SIZE;

    this->recv_len = recvmsg(this->sock_fd, &this->msg, 0);
    this->ip_out = (struct ip *)this->recv_pac;
    this->ip_in = inet_ntoa(this->ip_out->ip_src);

    if (strcmp(this->ip_last_vst, this->ip_in) == 0)
    {
        this->attempt = 3;
    }
    gettimeofday(&this->time_fin, (struct timezone *)NULL);
    get_time(&this->time_fin, &this->time_strt);
    rtt = (this->time_fin.tv_sec * 10000 + (this->time_fin.tv_usec / 100));
    this->rtt_s[this->attempt] = rtt;
}

static int _print_tr(trace_route *this)
{
    char name_h[NI_MAXHOST];
    struct sockaddr_in ip_d;

    this->ip_out = (struct ip *)this->recv_pac;
    this->ip_len = this->ip_out->ip_hl << 2;
    this->ip_in = inet_ntoa(this->ip_out->ip_src);

    if (strcmp(this->ip_last_vst, this->ip_in) == 0)
    {
        printf("%2d  * * *\n", this->ttl_cur);
        return 0;
    }
    strcpy(this->ip_last_vst, this->ip_in);
    this->recv_len -= this->ip_len;
    this->icmp = (struct icmp *)(this->recv_pac + this->ip_len);
    ip_d.sin_family = AF_INET;

    inet_pton(AF_INET, this->ip_in, &ip_d.sin_addr);
    if (getnameinfo((struct sockaddr *)&ip_d, sizeof(ip_d), name_h, sizeof(name_h), NULL, 0, 0) != 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s\n", tr_lab, "getnameinfo");
        perror(str_err);
        exit(EXIT_FAILURE);
    }
    printf("%2d  ", this->ttl_cur);
    pnip(name_h, this->ip_in, this->rtt_s);
    if ((strcmp(name_h, this->target)) == 0)
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

    this->go = (struct sockaddr_in *)&this->going;
    this->com = (struct sockaddr_in *)&this->comming;

    this->ttl_max = ttl_max;
    this->ttl_beg = 1;
    this->ttl_cur = this->ttl_beg;
    this->target = target;

    this->id = (getpid() & 0xffff) | 0x0000;
    return this;
}
int main(int argc, char *argv[])
{
    int fin = 0;
    if (argc == 0)
    {
        char str_err[50];
        sprintf(str_err, "%s%s", tr_lab, "Trace route requires an argument.");
        perror(str_err);
        exit(EXIT_FAILURE);
    }

    trace_route *tr = BEGIN_TRACE_ROUTE(argv[1], 30);
    tr->attempt = 0;
    tr->get_addr_info(tr);
    /**
        printf("trace route to %s (%s), %d hops max, %d byte packets\n", tr->target, tr->hip, tr->ttl_max, DATALEN + 8);
*/
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
    return 0;
}