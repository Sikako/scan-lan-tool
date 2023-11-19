#ifndef __PCAP__H_
#define __PCAP__H_

#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "fill_packet.h"

#define FILTER_STRING_SIZE 100
#define IMMEDIATE_MODE 0

extern char* net;
extern char* mask;
extern struct timeval sent_time, received_time; 

// Init pcap
void my_pcap_init(char* dev, int timeout);

// Receive Reply Packet and Print out 
const u_char* pcap_get_reply(char* c_dst_ip);

// Return Round-Trip Time
double calculate_rtt(struct timeval sent_time, struct timeval received_time);
#endif
