#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

unsigned int checksum(unsigned short * data, int len);
void exit_handler(int signum);
void mes_handler(int signum);

#endif
