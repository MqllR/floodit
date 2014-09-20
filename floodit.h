#include <linux/icmp.h>	  /* ICMP header */
#include <linux/udp.h>	  /* UDP header */
#include <linux/ip.h>   /* IP header */
#include <linux/tcp.h>	  /* TCP header */
#include <netinet/in.h>	   /* include socket.h and contain the declaration of sockaddr_in */

unsigned short csum(unsigned short *ptr,int nbytes);
void usage();
void sendflood_to(int sock, const char *packet, struct sockaddr_in *dest);
void sendflood(int sock, char *packet);
void send_inf_loop(char *proto, int sock, char *packet, struct iphdr *ip, struct sockaddr_in dest_addr, unsigned int speed);
void send_nloops(int nbpacket, char *proto, int sock, char *packet, struct iphdr *ip, struct sockaddr_in dest_addr, unsigned int speed);
void ip_header(struct iphdr *ip, int packet_size, int proto, const char *saddr, const char *daddr);
void icmp_header();
void tcp_header(int port_dst);
void udp_header(int port_dst);
int init_raw_connection(struct iphdr *ip, struct sockaddr_in *dest_addr, const char *target, const char *ip_dest, char *packet, const char *proto, int port);
