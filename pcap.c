#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>


extern pid_t pid;
extern u16 icmp_req;

// 修改interface name

char* net;
char* mask;

static char filter_string[FILTER_STRING_SIZE] = "icmp";

static pcap_t *p;
static struct pcap_pkthdr hdr;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void my_pcap_init( const char* dst_ip, char* dev ,int timeout)
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	
	struct bpf_program fcode;
	

	// 1. Looks up the network address and mask of the device.
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}
	
	//2. Converts the network and mask addresses from numeric to string format.
	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	printf("%d\n", netp);
	puts(net);
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	
	printf("%d\n", maskp);
	puts(mask);

	//3. Opens the device for live capture.
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	
	//4. Compiles the filter expression into a format that pcap can read.
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


const u_char* pcap_get_reply( void )
{
	const u_char *ptr;

	ptr = pcap_next(p, &hdr);
	
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
	
	
	
	return ptr;
}