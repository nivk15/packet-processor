#include <stdio.h>           // printf
#include <stdlib.h>          // exit
#include <sys/socket.h>      // socket, recvfrom
#include <netinet/in.h>      // htons
#include <linux/if_ether.h>  // ETH_P_ALL


int main() {

    // Part 1
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

    // Part 2
    struct ethhdr *eth = (struct ethhdr *)buffer;

    printf("----------------------------------------\n");
    printf("mac destination: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("mac source: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("EtherType: %04x\n", ntohs(eth->h_proto));

    // Part 3
    
}