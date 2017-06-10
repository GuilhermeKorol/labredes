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

int main(){
	int fd;
	struct ifreq ethreq;
	int i, size;
	unsigned char buffer[PCKT_LEN]; 
	
	/* Cria o Socket Raw */
	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("socket:");
		return -1;
	}
	
	/* Coloca o adaptador de rede em modo promíscuo */
	strncpy(ethreq.ifr_name, "enp4s0", IFNAMSIZ);
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
		printf("\n%d:\t", size);
		
		/* exibe os primeiros 14 bytes,  ou seja,
		MAC Address Destino, Mac Address Origem e type do cabeçalho Ethernet */
		printf("target: ");
		for (i = 0; i < 6; i++)
			printf("%02x ", buffer[i]);
		printf(" source: ");
		for (i = 6; i < 12; i++)
			printf("%02x ", buffer[i]);
		printf(" protocol: %04x", (buffer[12] << 8) | buffer[13]);
	}

	return 0;
}
