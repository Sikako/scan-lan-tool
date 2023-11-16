#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>



void  fill_iphdr (myicmp* packet, struct in_addr my_ip, struct in_addr dst_ip){
    packet->ip_hdr.ip_hl = 5;
    packet->ip_hdr.ip_v = 4;
	packet->ip_hdr.ip_tos = 0;
    packet->ip_hdr.ip_len = htons(PACKET_SIZE);
    packet->ip_hdr.ip_id = 0;
    packet->ip_hdr.ip_off = 0;
    packet->ip_hdr.ip_ttl = 1;
    packet->ip_hdr.ip_p = 1;
    packet->ip_hdr.ip_src = my_ip;
    packet->ip_hdr.ip_dst = dst_ip;

}

void fill_icmphdr (myicmp* packet, struct icmphdr *icmp_hdr)
{
	
}

u16 fill_cksum(struct icmphdr* icmp_hdr)
{
	
}