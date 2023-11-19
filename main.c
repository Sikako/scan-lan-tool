#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>

#include "fill_packet.h"
#include "pcap.h"
#include "debug_tools.h"
#define IFNAMESIZE 10
#define DEBUG 1

void check_format(int);
void check_root();
void usage();
int get_net_num(char*);


int main(int argc, char* argv[]){
	int sockfd;
	int on = 1;
	
	char* p_dev = NULL;
	int timeout;
	struct sockaddr_in sa;
	struct in_addr my_ip;
	struct in_addr* p_my_ip = &my_ip;
	struct in_addr dst_ip;
	struct ifreq ifr;
	uint8_t buffer[PACKET_SIZE];
	myicmp *packet = (myicmp*)buffer;
	const unsigned char* p_packet_reply;
	int count = DEFAULT_SEND_COUNT;
	int i;
	int option;
	int net_num;

	check_root();

	check_format(argc);

	// Get Options
	while((option = getopt(argc, argv, "i:t:")) != -1){
			switch (option){
				case 'i':
					p_dev = strdup(optarg);
					break;
			
				case 't':
					timeout = atoi(optarg);
					break;

				default:
					usage();
					break;
			}
		}


	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
		{
			perror("socket");
			exit(1);
		}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
	// Get Interface IP ---------------------------------------------
 	ifr.ifr_addr.sa_family = AF_INET;
 	memcpy(ifr.ifr_name, (const char* )p_dev, IFNAMESIZE);
	// puts(ifr.ifr_name); //ens33
 	ioctl(sockfd, SIOCGIFADDR, &ifr);
	memcpy(p_my_ip, (struct in_addr*)&(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr), sizeof(struct in_addr));
	// printf("%d\n", ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
	// // printf("%d\n", my_ip.s_addr);
	// // printf("%s\n", inet_ntoa(my_ip));
	// // printf("%d\n", inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	// printf("192.168.203.1: %x\n", ntohl(inet_addr("192.168.203.1")));
	// printf("192.168.203.2: %x\n", ntohl(inet_addr("192.168.203.2")));
	// printf("255.255.255.0: %0x\n", inet_addr("255.255.255.0"));

	c_my_ip = strdup(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	// puts(c_my_ip);
	// // puts(net);
	// // puts(mask);

	// Initialize Pcap ---------------------------------------------
	my_pcap_init(p_dev , timeout);
	net_num = get_net_num(mask);	// Get net number
	// printf("net num: %d\n", net_num);
	
	
	// /*
	//  *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
	// 	 or use the standard socket like the one in the ARP homework
 	//  *   to get the "ICMP echo response" packets 
	//  *	 You should reset the timer every time before you send a packet.
	//  */

	for(int i = 1; i < net_num; i++){
	// // Seting buffer-------------------------------------------
		memset(buffer, 0, sizeof(buffer));
		// print_buffer(buffer, PACKET_SIZE);
		
		
		dst_ip.s_addr = htonl(ntohl(inet_addr(net)) + i);
		c_dst_ip = inet_ntoa(dst_ip);
		// printf("%x\n", dst_ip.s_addr);
		fill_iphdr(packet, my_ip, dst_ip);
		fill_icmphdr(packet);
		print_buffer(buffer, PACKET_SIZE);
		sa.sin_family = AF_INET;
    	sa.sin_addr.s_addr = dst_ip.s_addr;

		// // Send Packet
		if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		{
				perror("sendto");
				exit(1);
		}
		// // Record the time when the packet is sent
		gettimeofday(&sent_time, NULL);

		printf("PING %s (data size = %d, id = %x, seq = %d, timeout = %d ms)\n", c_dst_ip, (int)sizeof(packet->data), packet->icmp_hdr.id, ntohs(packet->icmp_hdr.seq), timeout);

		p_packet_reply = pcap_get_reply(c_dst_ip);
		if(p_packet_reply == NULL){
			perror("pcap_get_reply");
			exit(1);
		}
	}

	

	return 0;
}


void check_root(){
	pid = geteuid();
	if (pid != 0){
		printf("ERROR: You must be root to use this tool!\n");
		exit(1);
	}
}

void check_format(int argc){
	if (argc != 5){
		usage();
		exit(1);
	}
}

void usage(){
	puts("sudo ./ipscanner –i [Network Interface Name] -t [timeout(ms)]");
}

int get_net_num(char* mask){
	// puts(mask);
	// printf("%06x\n", htonl(inet_addr(mask)));
	return ~(0xffffffff & ntohl(inet_addr(mask)));
}