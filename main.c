#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#include <stdio.h>
#include "structs.h"

int tcp=0, udp=0, icmp=0, others=0, total=0;


// Initialize Winsock
void initialize_winsocks()
{
	WSADATA wsa;
    printf("Initializing Winsock... ");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
    {
        printf("WSAStartup() failed.\n");
        exit(1);
    }
    printf("Initialized.\n");
}


// Create a RAW Socket
SOCKET create_raw_socket()
{
    SOCKET raw_socket;
	raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_socket == INVALID_SOCKET)
    {
        printf("Failed to create raw socket.\n");
        printf("Administrator privilege are required to continue.\n");
        exit(1);
    }
	return raw_socket;
}


// Retrieve the local hostname
struct hostent * get_host()
{
	struct hostent *local_host;
	char hostname[100];
    // Retrieve the local hostname
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
    {
		printf("WSAGetLastError : %d\n", WSAGetLastError());
		exit(1);
    }
	// Retrieve all local ips
	local_host = gethostbyname(hostname);
	if (local_host == NULL)
    {
		printf("WSAGetLastError : %d\n", WSAGetLastError());
    }
	return local_host;
}


// Ask which network interface to use
int ask_for_interface(struct hostent *local_host)
{
	int number_of_interfaces = 0; // number of network interfaces available on localhost
    int interface_index = -1; // choice made by user for the interface
    struct in_addr addr;

	//Retrieve the available IPs of the local host
	printf("Available Network Interfaces :\n");
    for (number_of_interfaces = 0; local_host->h_addr_list[number_of_interfaces] != 0; ++number_of_interfaces)
    {
        memcpy(&addr, local_host->h_addr_list[number_of_interfaces], sizeof(struct in_addr));
		printf("*** [%d] - Address : %s\n", number_of_interfaces, inet_ntoa(addr));
    }

    // if there is only one interface available, automatically choose it
    if (number_of_interfaces == 1)
    {
        interface_index = 0;
    }
    else
    {
		printf("Enter the interface you would like to sniff : \n");
        scanf("%d", &interface_index);
    }

	printf("Use interface %d\n\n", interface_index);

    return interface_index;
}

// Assigning a name to a socket
void bind_socket(SOCKET raw_socket, struct hostent *local_host)
{
	struct sockaddr_in dest;
	int interface_index = 0;
	int j=1;

    // Ask the interface number if no interface was specified in argument
    interface_index = ask_for_interface(local_host);

	// Retrieve the available IPs of the local host
    memset(&dest, 0, sizeof(dest));
    memcpy(&dest.sin_addr.s_addr, local_host->h_addr_list[interface_index], sizeof(dest.sin_addr.s_addr));
    dest.sin_family = AF_INET;
    dest.sin_port = 0;

	// Bind the socket to the local IP over which the traffic is to be sniffed
    if (bind(raw_socket, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
    {
        printf("Bind failed.\n");
        exit(1);
    }

    // Call WSAIoctl() on the socket to five it sniffing powers
    if (WSAIoctl(raw_socket, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &interface_index , 0 , 0) == SOCKET_ERROR)
    {
        printf("WSAIoctl() failed.\n");
        exit(1);
    }
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

	printf("\n\n***********************UDP Packet*************************\n");
	printf("IP Header\n");
	printf(" |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	printf(" |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
	printf("\nUDP Header\n");
	printf(" |-Source Port : %d\n", ntohs(udpheader->source_port));
	printf(" |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	printf("\n");
	printf("\n###########################################################");
}


void process_packet(char* buffer)
{
	IPV4_HDR *iphdr;

	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)buffer;
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
        recv_size = recvfrom(raw_socket , buffer , frame_max_size , 0 , 0 , 0);
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
    // Initialize Winsock
    initialize_winsocks();

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
