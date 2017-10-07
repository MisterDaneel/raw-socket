#include <stdlib.h> /* exit */
#include <sys/socket.h>
#include <sys/ioctl.h> // SIOCGIFINDEX
#include <netinet/if_ether.h> // ETH_P_IP, ethhdr
#include <net/if.h> // ifreq
#include <netdb.h> // gethostbyname
#include <linux/if_packet.h> // sockaddr_ll
#include <arpa/inet.h>
#define closesocket(s) close(s)
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef struct in_addr IN_ADDR;

// Create a RAW Socket
SOCKET create_raw_socket()
{
	SOCKET raw_socket;

    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));//ntohs(0x0003));
    // setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, "eth1", strlen("eth1")+1);

    if (raw_socket < 0)
    {
        printf("Failed to create raw socket.\n");
        printf("Administrator privilege are required to continue.\n");
        exit(1);
    }

	return raw_socket;
}

// Assigning a name to a socket
void bind_socket(SOCKET raw_socket, struct hostent *local_host)
{
    struct sockaddr_ll sll;//sockaddr_ll sll;
    struct ifreq ifr;

    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    strncpy((char *)ifr.ifr_name, "eth1", IFNAMSIZ);
    if ((ioctl(raw_socket, SIOCGIFINDEX, &ifr)) == -1)
    {
        printf("Error getting the interface index\n");
        exit(1);
    }

    sll.sll_family = AF_PACKET; // Address family
    sll.sll_ifindex = ifr.ifr_ifindex; // Interface index
    sll.sll_protocol = htons(ETH_P_IP); // Link layer protocol

    if ((bind(raw_socket, (struct sockaddr *)&sll, sizeof(sll))) == -1)
    {
        printf("Bind failed.\n");
        exit(1);
    }
}
