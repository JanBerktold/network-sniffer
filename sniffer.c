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

int file_handle;

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	char log[4+pkthdr->len+2];

	memcpy(log, &pkthdr->len, 4);
	memcpy(log+4, packet, pkthdr->len);
 	log[sizeof(log)-1]='\0';

	printf("%lu", sizeof(pkthdr->len));
	if(write(file_handle, log, sizeof(log)) <= 0)
	{
		printf("something went wrong %s\n", strerror(errno));
		exit(-1);
	}

  printf("Packet number [%d], length of this packet is: %d\n", count++, pkthdr->len);
}

void shutdown_handler(int sig)
{
	if (file_handle > -1)
	{
		close(file_handle);
		file_handle = -1;
		exit(0);
	}
}

int main(int argc,char **argv)
{
    char *dev;
    pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/

    // open file
    file_handle = open("output", O_APPEND|O_CREAT|O_WRONLY);
    if (file_handle< 0)
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
        return -1;
    }

	signal(SIGINT, shutdown_handler);
	signal(SIGKILL, shutdown_handler);
	signal(SIGTERM, shutdown_handler);

    // For every packet received, call the callback function
    pcap_loop(descr,-1, callback, NULL);

    return 0;
}
