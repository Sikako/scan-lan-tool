#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>

#include "fill_packet.h"
#include "pcap.h"
#include "debug_tools.h"
#define IFNAMESIZE 10

extern char* optarg;
extern char* net;
extern char* mask;

void check_format(int);
void check_root();
void usage();

pid_t pid;

int main(int argc, char* argv[]){
	int sockfd;
	int on = 1;
	
	char* p_dev = NULL;
	char* c_my_ip = NULL;
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

	
	const char* target_ip = "hihi";
	
	
	check_root();
	check_format(argc);


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

	my_pcap_init( target_ip, p_dev , timeout);

	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	

 	ifr.ifr_addr.sa_family = AF_INET;
 	memcpy(ifr.ifr_name, (const char* )p_dev, IFNAMESIZE);
	// puts(ifr.ifr_name);
 	ioctl(sockfd, SIOCGIFADDR, &ifr);
	memcpy(p_my_ip, (struct in_addr*)&(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr), sizeof(struct in_addr));
	// printf("%d\n", my_ip.s_addr);
	// printf("%s\n", inet_ntoa(my_ip));
	// printf("%d\n", inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	c_my_ip = strdup(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	// puts(c_my_ip);
	// puts(net);
	// puts(mask);
	
	memset(buffer, 0, sizeof(buffer));
	print_buffer(buffer, PACKET_SIZE);

	dst_ip.s_addr = inet_addr("192.168.203.1");
	fill_iphdr(packet, my_ip, dst_ip);
	fill_icmphdr(packet);
	fill_icmpdata(packet);
	print_buffer(buffer, PACKET_SIZE);
	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */

	sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("192.168.203.1");


	 if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
			perror("sendto");
			exit(1);
	}

	p_packet_reply = pcap_get_reply();
	if(p_packet_reply == NULL){
		perror("pcap_get_reply");
		exit(1);
	}
	

	// free(packet);

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
