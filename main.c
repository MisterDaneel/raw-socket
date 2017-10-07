#ifdef _WIN32
    #include "socket_windows.h"
#elif __linux__
    #include "socket_linux.h"
#endif

#include <stdio.h>
#include "structs.h"

int tcp=0, udp=0, icmp=0, others=0, total=0;


// Retrieve the local hostname
struct hostent * get_host()
{
	struct hostent *local_host;
	char hostname[100];
    // Retrieve the local hostname
    if (gethostname(hostname, sizeof(hostname)) == -1)
    {
		printf("Get host name: SOCKET_ERROR\n");
		exit(1);
    }
	// Retrieve all local ips
	local_host = gethostbyname(hostname);
	if (local_host == NULL)
    {
		printf("Get host by name: NULL\n");
    }
	return local_host;
}

void process_tcp_packet(IPV4_HDR *iphdr, char *buffer)
{
	TCP_HDR *tcpheader;
	struct sockaddr_in source,dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	tcpheader=(TCP_HDR*)buffer;

	printf("\n\n***********************TCP Packet*************************\n");
	printf("IP Header\n");
	printf(" |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	printf(" |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
	printf("TCP Header\n");
	printf(" |-Source Port : %u\n",ntohs(tcpheader->source_port));
	printf(" |-Destination Port : %u\n",ntohs(tcpheader->dest_port));
	printf("\n");
	printf("\n###########################################################");
}


void process_udp_packet(IPV4_HDR *iphdr, char *buffer)
{
	UDP_HDR *udpheader;
	struct sockaddr_in source,dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	udpheader = (UDP_HDR *)buffer;
/*
	printf("\n\n***********************UDP Packet*************************\n");
	printf("IP Header\n");
	printf(" |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	printf(" |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
	printf("\nUDP Header\n");
	printf(" |-Source Port : %d\n", ntohs(udpheader->source_port));
	printf(" |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	printf("\n");
	printf("\n###########################################################");
*/
}


void process_packet(char* buffer)
{
    IPV4_HDR *iphdr;
    unsigned short iphdrlen;

#ifdef _WIN32
    iphdr = (IPV4_HDR *)buffer;
#elif __linux__
    iphdr = (IPV4_HDR *)(buffer + sizeof(struct ethhdr));
#endif

	iphdrlen = iphdr->ip_header_len*4;

	switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
	{
		case 1: //ICMP Protocol
		++icmp;
		break;

		case 6: //TCP Protocol
		process_tcp_packet(iphdr, buffer + iphdrlen);
		++tcp;
		break;

		case 17: //UDP Protocol
		process_udp_packet(iphdr, buffer + iphdrlen);
		++udp;
		break;

		default: //Some Other Protocol like ARP etc.
		++others;
		break;
	}
	printf("\n\n");
	printf("TCP : %d UDP : %d ICMP : %d Others : %d Total : %d\r", tcp, udp, icmp, others, total);
	++total;
}


// loop
void start(SOCKET raw_socket)
{
	int frame_max_size = 65536;
	char *buffer = (char *)malloc(frame_max_size);
    int recv_size = 0;
    do
    {
        recv_size = recvfrom(raw_socket, buffer, frame_max_size, 0, 0, 0);
        if(recv_size > 0)
        {
            process_packet(buffer);
        }
        else
        {
            printf("recvfrom() failed.\n");
        }

    } while (recv_size > 0);

}

int main()
{
	SOCKET raw_socket;
	struct hostent *local_host;  //LocalHost

	// Create a RAW Socket
	raw_socket = create_raw_socket();

	// Retrive the local hostname
	local_host = get_host();

	// Assigning a name to a socket
	bind_socket(raw_socket, local_host);

	// Recvfrom loop
	start(raw_socket);

	return 0;
}
