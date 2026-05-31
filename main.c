#include <stdio.h>           // printf
#include <stdlib.h>          // exit
#include <sys/socket.h>      // socket, recvfrom
#include <netinet/in.h>      // htons
#include <linux/if_ether.h>  // ETH_P_ALL


int main() {

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65535];

    int packet_size = recvfrom(sock, buffer, 65535, 0, NULL, NULL);
    if (packet_size == -1) {
        perror("recvfrom");
        return 1;
    }

    for (int i = 0; i < packet_size; i++){
        printf("%02x ", buffer[i]);
    }

    printf("\n");
}