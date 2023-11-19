#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>

typedef unsigned char u8;
typedef unsigned short u16;

#define IP_HEADER_SIZE 20
#define IP_OPTION_SIZE 8
#define ICMP_HEADER_SIZE 8
#define ICMP_DATA_SIZE 10
#define ICMP_PACKET_SIZE ICMP_HEADER_SIZE + ICMP_DATA_SIZE
#define PACKET_SIZE IP_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

extern pid_t pid;
extern char* c_my_ip;
extern char* c_dst_ip;

struct myicmphdr {
	u8 type;
	u8 code;
	u16 cksum;
	u16 id;
	u16 seq;
};

typedef struct 
{
	struct ip ip_hdr;
	// u8 ip_option[8];
	struct myicmphdr icmp_hdr;
	u8 data[10];
} myicmp;

void fill_iphdr(myicmp *packet, struct in_addr my_ip, struct in_addr dst_ip);

void fill_icmphdr(myicmp *packet);

void fill_icmpdata(myicmp *packet);

u16 fill_cksum(u16 *, int len);

#endif
