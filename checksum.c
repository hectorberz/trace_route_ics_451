#include <sys/types.h>
/**
 * Based on in_chksum() from Unix NEtwork Programming by Stevens,
 * Fenner, and Rudoff
 **/

unsigned short checksum(unsigned short *data, int len)
{
    int i;
    unsigned int sum = 0;
    unsigned short *ptr;
    unsigned short chcksum;

    for (i = len, ptr = data; i > 1; i -= 2)
    {
        sum += *ptr;
        ptr += 1;
    }
    if (i == 1)
    {
        sum += *((unsigned char *)ptr);
    }

    sum = (sum & 0xffff) + (sum >> 16);

    sum += (sum >> 16);

    chcksum = ~sum;

    return chcksum;
}
