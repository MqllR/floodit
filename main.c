/***************************************************/
/* floodit is used to test the security of your    */
/* own server. It send ICMP, TCP or UDP packets    */
/* with modify headers. You can spoof IP address,  */
/* choose your target with IP broadcast...	   */
/*						   */
/* Compilation : gcc -o floodit floodit.c	   */
/* Run with root privilege : 			   */
/* ./floodit -h 	to get more information	   */
/*						   */
/* Contact : ride_online@hotmail.fr		   */
/***************************************************/

#include "floodit.h"

#include <arpa/inet.h>	// htons, inet_addr ...
#include <stdio.h>   // perror, printf
#include <stdlib.h>   // Flags, exit
#include <string.h>	// memset, memcpy
#include <unistd.h>	// close, getuid, getopt
#include <errno.h>

extern char *optarg;
extern int optind, opterr, optopt;


int main(int argc, char **argv)
{
	struct iphdr *ip;	/* Header IP */
	struct sockaddr_in dest_addr;	/* Interface dest */
	int sock;
	int ch;
	char *packet;	/* Packet to send */
	char *proto = NULL;
	char *ipaddr_spoofed = NULL;
	char payload[] = "Hello !";
	unsigned int port = 80, speed = 1, nbpacket = 0; /* Options by default */


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
/* PROBLEME ENCODAGE || ??	if(strncmp(optarg, "icmp", 4) != 0 || strncmp(optarg, "tcp", 3) != 0 || strncmp(optarg, "udp", 3) != 0)
	//			if(strncmp(optarg, "icmp", 4) != 0)
	//			{
	//				printf("Error with option -t (Only the values icmp, tcp or udp are available)\n");
	//				exit(EXIT_FAILURE);
				} */
				proto = optarg;
				break;
			case 'q':
				speed = atoi(optarg);
				if(speed > 3 || (speed < 1)) {
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
		printf("Option -t or -s are missing\t --\tUse -h to get some help\n");
		exit(EXIT_FAILURE);
	}

	printf("+---------------------------------------+\n");
	printf("| Dst addr : %s\t\t\t|\n", argv[argc - 1]);
	printf("| Src addr : %s \t\t\t|\n", ipaddr_spoofed);
	if(strncmp(proto,"icmp", 4) != 0)
		printf("| Port : %d\t\t\t\t|\n", port);
	printf("| Nb packet : %d\t\t\t|\n", nbpacket);
	printf("| Speed : %d\t\t\t\t|\n", speed);
	printf("+---------------------------------------+\n\n");


	/* Allocate memory */
	ip = (struct iphdr *) malloc(sizeof(struct iphdr));

/*	PROBLEME LORS DE L'INITIALISATION	
	if(strncmp(proto, "icmp", 4) == 0) {
		packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(payload));
		memset(packet, sizeof(struct iphdr) + sizeof(struct icmphdr), 0); 
	}
	else if(strncmp(proto, "tcp", 3) == 0) {
		packet = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(payload));
		memset(packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0); 
	}
	else { 
		packet = malloc(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(payload));
		memset(packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0); 
	}  */

	/* Init the different header */
	sock = init_raw_connection(ip, &dest_addr, ipaddr_spoofed, argv[argc - 1], packet, proto, port);

	if(nbpacket == 0)
		send_inf_loop(proto,sock, packet, ip, dest_addr, speed);
	else
		send_nloops(nbpacket, proto, sock, packet, ip, dest_addr, speed);

	free(ip);

	close(sock);	/* Close socket */

	return EXIT_SUCCESS;
}
