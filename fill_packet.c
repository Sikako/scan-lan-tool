#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

pid_t pid = 0;
char* c_my_ip = NULL;
char* c_dst_ip = NULL;

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
    struct myicmphdr* p = &packet->icmp_hdr;
	p->type = ICMP_ECHO;
    p->code = 0;
    p->id = htons(pid);
    p->seq = htons(1);
    fill_icmpdata(packet);
    p->cksum = htons(fill_cksum((u16*)p, ICMP_PACKET_SIZE));
}

void fill_icmpdata(myicmp* packet){
    char* student_id = "M123140001";
    memcpy(packet->data, student_id, 10);
}

u16 fill_cksum(u16* hdr, int len) {
    unsigned long sum = 0;

    while(len > 1){
        // printf("sum: %04lx, hdr: %04x\n",sum, *hdr);
        sum += ntohs(*hdr);
        hdr++;
        len -= 2;
    }

       if(len == 1)       /* take care of left over byte */
         sum += (unsigned char) *hdr;

       while(sum>>16){
        sum = (sum & 0xFFFF) + (sum >> 16);
        // printf("sum>%ld\n", sum);
       }
        

        // printf("~sum: %4lx\n", ~sum);
        return (u16)~sum;
}