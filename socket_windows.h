#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

// Initialize Winsock
void initialize_winsocks()
{
#ifdef _WIN32
	WSADATA wsa;
    printf("Initializing Winsock... ");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
    {
        printf("WSAStartup() failed.\n");
        exit(1);
    }
    printf("Initialized.\n");
#endif
}

// Create a RAW Socket
SOCKET create_raw_socket()
{
	SOCKET raw_socket;

    initialize_winsocks();

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_socket == -1)
    {
        printf("Failed to create raw socket.\n");
        printf("Administrator privilege are required to continue.\n");
        exit(1);
    }
	return raw_socket;
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

	int j=1;
	int interface_index = 0;

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
