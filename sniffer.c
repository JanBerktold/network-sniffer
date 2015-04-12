#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <zlib.h>

unsigned long const static WRITE_BUFFER_SIZE = 1024 * 10;

gzFile file_handle;
char* write_buffer;
int write_progress = 0;

void flush_data()
{
	int written_bytes = gzwrite(file_handle, write_buffer, write_progress);
	if(written_bytes <= 0) {
		printf("something went wrong while writing %d", written_bytes);
		exit(-1);
	}
	printf("wrote %d bytes from %d buffer\n", written_bytes, write_progress);
	write_progress = 0;
}

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	unsigned long data_size = 4+pkthdr->len;

	if (write_progress + data_size > WRITE_BUFFER_SIZE) {
		flush_data();	
	}
	char* log = malloc(data_size);

	memcpy(write_buffer+write_progress, &pkthdr->len, 4);
	memcpy(write_buffer+write_progress+4, packet, pkthdr->len);
	
	write_progress += data_size;
//	printf("Packet number [%d], length of this packet is: %d\n", count++, pkthdr->len);
}

void shutdown_handler(int sig)
{
	if (file_handle)
	{
		flush_data();	
		gzclose(file_handle);
		exit(0);
	}
}

void set_filters(char* dev, pcap_t* descr, bpf_u_int32* netp)
{
	struct bpf_program fp;
	if (pcap_compile(descr, &fp, "tcp", 0, *netp) < 0)
	{
		printf("error while compiling\n");
		exit(-1);
	}

	if (pcap_setfilter(descr, &fp) < 0) 
	{
		printf("error setting filter\n");
		exit(-1);
	}
}

int main(int argc,char **argv)
{
	char *dev;
	pcap_t* descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 pMask;            /* subnet mask */
	bpf_u_int32 pNet;             /* ip address*/

	write_buffer = malloc(WRITE_BUFFER_SIZE);

	// open file
	file_handle = gzopen("output", "wb");
	if (!file_handle)
	{
		printf("Error while opening file\n");
		return -1;
	}

	dev = pcap_lookupdev(errbuf);

	// If something was not provided
	// return error.
	if(dev == NULL)
	{
		printf("\n[%s]\n", errbuf);
		return -1;
	}

	// fetch the network address and network mask
	pcap_lookupnet(dev, &pNet, &pMask, errbuf);

	// Now, open device for sniffing
	descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		exit(-1);
	}

	set_filters(dev, descr, &pNet);

	signal(SIGINT, shutdown_handler);
	signal(SIGKILL, shutdown_handler);
	signal(SIGTERM, shutdown_handler);

	// For every packet received, call the callback function
	pcap_loop(descr,-1, callback, NULL);

	return 0;
}
