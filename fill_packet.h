#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef unsigned char u8;
typedef unsigned short u16;

#define PACKET_SIZE    38
#define IP_OPTION_SIZE 8
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int) sizeof(struct ip)
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int) sizeof(struct icmphdr)
#define ICMP_HEADER_SIZE   ICMP_PACKET_SIZE - ICMP_DATA_SIZE
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

typedef struct{
	struct ip ip_hdr;
	// u8 ip_option[8];
	struct icmp icmp_hdr;
	u8 data[10];
} myicmp;

void  fill_iphdr (myicmp* packet, struct in_addr my_ip, struct in_addr dst_ip);

void fill_icmphdr (myicmp* packet);

void fill_icmpdata (myicmp* packet);

u16 fill_cksum (u16*, int len);
 
#endif
 