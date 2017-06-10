#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>

/* tamanho máximo de um frame Ethernet*/
#define PCKT_LEN 1518
/* ip header offset no buffer de entrada */
#define IP_OFFSET 14

int main(){
	int fd;
	struct ifreq ethreq;
	int i, j, size;
	unsigned char buffer[PCKT_LEN];
	unsigned char ip_dst[4] = {0};
	unsigned char ip_src[4] = {0};
	uint16_t port_dst = 0;
	uint16_t port_src = 0;

	/* Cria o Socket Raw */
	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
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

	while ((size = read(fd, buffer, PCKT_LEN)) > 0){
		/* Exibe tamanho do pacote recebido */
		// printf("\n%d:\t", size);

		if(buffer[12] == 0x08 && buffer[13] == 0x00) {
			printf("IP HEADER FOUND:\n");
			printf("    Protocol %04x\n", buffer[IP_OFFSET+9]);
			printf("    IP source: ");
			for (i = IP_OFFSET+12,j=0; i < IP_OFFSET+16,j<3; i++,j++){
				printf("%d ", buffer[i]);
				ip_src[j] = buffer[i];
			}
			printf("\n   IP destination: ");
			for (i = IP_OFFSET+16; i < IP_OFFSET+20; i++)
				printf("%d ", buffer[i]);
		}


	}

	return 0;
}
