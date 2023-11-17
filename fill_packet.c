#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

extern pid_t pid;

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

void fill_icmphdr (myicmp* packet){
    struct icmp* p = &packet->icmp_hdr;
	p->icmp_type = ICMP_ECHO;
    p->icmp_code = 0;
    p->icmp_id = htons(pid);
    p->icmp_seq = htons(1);
    p->icmp_cksum = fill_cksum((u16*)p, 8);
    printf("%d\n", p->icmp_cksum);
}

void fill_icmpdata(myicmp* packet){
    char* student_id = "M123140001";
    memcpy(packet->data, student_id, sizeof(packet->data));
}

u16 fill_cksum(u16* hdr, int len) {
    unsigned long sum = 0;

    while(len > 1){
         sum += *hdr++;
         len -= 2;
       }

       if(len == 1)       /* take care of left over byte */
         sum += (unsigned char) *hdr;

       while(sum>>16)
         sum = (sum & 0xFFFF) + (sum >> 16);

       return ~sum;
}