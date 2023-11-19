#include <sys/types.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "pcap.h"
#include "fill_packet.h"



// extern u16 icmp_req; 
struct timeval sent_time = {}, received_time = {};

char* net = NULL;
char* mask = NULL;

static char filter_string[FILTER_STRING_SIZE] = {0};

static pcap_t *p;
static struct pcap_pkthdr *hdr;
static const u_char *content;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void my_pcap_init(char* dev ,int timeout){	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	static struct in_addr a_net, a_mask;
	
	struct bpf_program fcode;
	

	// 1. Looks up the network address and mask of the device.
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}
	
	//2. Converts the network and mask addresses from numeric to string format.
	a_net.s_addr = netp;
	net = strdup(inet_ntoa(a_net));
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}

	a_mask.s_addr = maskp;
	mask = strdup(inet_ntoa(a_mask));
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}

	// net = inet_ntoa(a_net);	
	// puts(net);
	// printf("%d\n", maskp);
	// puts(mask);

	//3. Opens the device for live capture.
	p = pcap_create( dev, errbuf );
	if( p == NULL ){
		fprintf( stderr, "Unable to create pcap for interface %s (%s).\n", dev, errbuf );
		exit(1);
	}
	// p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	// if(!p){
	// 	fprintf(stderr,"%s\n",errbuf);
	// 	exit(1);
	// }

	if( pcap_set_timeout( p, timeout ) != 0 )
	{
		fprintf( stderr, "Unable to configure timeout.\n" );
		exit(1);
	}

	if( pcap_set_immediate_mode( p, 1 ) != 0 )
	{
		fprintf( stderr, "Unable to configure immediate mode.\n" );
		exit(1);
	}

	ret = pcap_set_immediate_mode(p, IMMEDIATE_MODE);
	if(ret != 0){
		fprintf( stderr, "Unable to configure immediate mode.\n" );
		exit(1);
	}

	// Activate packet capture handle to look at packets on the network
	int activateStatus = pcap_activate( p );
	if( activateStatus < 0 )
	{
		pcap_perror( p, "Activate failed" );
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	
	//4. Compiles the filter expression into a format that pcap can read.
	// puts(c_dst_ip);
	// puts(c_my_ip);
	sprintf(filter_string, "icmp and dst host %s", c_my_ip);
	puts(filter_string);
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


const u_char* pcap_get_reply(char* c_dst_ip){
	int ret = pcap_next_ex(p, &hdr, &content);
	double rtt;
	
	// Record the time when the packet is received
    gettimeofday(&received_time, NULL);
	rtt = calculate_rtt(sent_time, received_time);

	if(ret == 1) {
		
		printf("\tReply from : %s , time : %.5f ms\n", c_dst_ip, rtt);
		
		// printf("Length: %d bytes\n", hdr->len);
		// printf("Capture length: %d bytes\n", hdr->caplen);

		// print packet in hex dump
		// for(int i = 0 ; i < hdr->caplen ; i++) {
		// 	printf("%02x ", content[i]);
		// 	if ((i+1) % 16 == 0 && i != 0)
		// 		printf("\n");
		// }
		// printf("\n\n");
	}
	else if(ret == 0) {
        printf("Destination unreachable\n");
    }//end if timeout
    else if(ret == -1) {
        fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(p));
    }//end if fail
    else if(ret == -2) {
        printf("No more packet from file\n");
    }//end if read no more packet

	return content;
	
}

double calculate_rtt(struct timeval sent_time, struct timeval received_time) {
    // 计算秒数差值，并将其转换为毫秒
    long int seconds_difference = received_time.tv_sec - sent_time.tv_sec;
    long int microseconds_difference = received_time.tv_usec - sent_time.tv_usec;

    // 计算 RTT，将秒数差值和微秒差值合并为毫秒
    long int rtt_microseconds = seconds_difference * 1000000 + microseconds_difference;
    double rtt_milliseconds = (double)rtt_microseconds / 1000.0;

    // 精确到小数点后五位
    return rtt_milliseconds;
}