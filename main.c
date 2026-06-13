#include <stdio.h>           // printf
#include <stdlib.h>          // exit
#include <sys/socket.h>      // socket, recvfrom
#include <netinet/in.h>      // htons
#include <linux/if_ether.h>  // ETH_P_ALL
#include <linux/ip.h>  


int main() {

    // Part 1 
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket");
        return 1;
    }


    while (1){

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
        //--------------------------------------------------------------------------------

        // Part 2  (parsing Ethernet header)
        struct ethhdr *eth = (struct ethhdr *)buffer;           // grep -A 5 "struct ethhdr" /usr/include/linux/if_ether.h

        if (ntohs(eth->h_proto) != 0x0800) continue;           // 0x0800 is the code for IPv4


        printf("----------------------------------------\n");
        printf("Ethernet header:\n");
        printf("mac destination: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("mac source: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("EtherType: %04x\n", ntohs(eth->h_proto));
        printf("----------------------------------------\n");
        //--------------------------------------------------------------------------------

        // Part 3  (parsing IP header)
        // if (ntohs(eth->h_proto) == 0x0800) {        // 0x0800 is the code for IPv4

        struct iphdr *ip = (struct iphdr *)(buffer + 14);           // grep -A 25 "struct iphdr" /usr/include/linux/ip.h

        if (ip->daddr == inet_addr("127.0.0.1") || ip->saddr == inet_addr("127.0.0.1")) continue;

        unsigned char *src = (unsigned char *)&(ip->saddr);
        unsigned char *dst = (unsigned char *)&(ip->daddr);

        printf("***\ncurrent dst value:  %d\n***\n", ip->daddr);

        printf("----------------------------------------\n");
        printf("IP header:\n");
        printf("version: %d\n", ip->version);
        printf("ihl: %d\n", ip->ihl);
        printf("tos: %02x\n", ip->tos);
        printf("tot_len: %d\n", ntohs(ip->tot_len));
        printf("id: %04x\n", ntohs(ip->id));
        printf("frag_off: %04x\n", ntohs(ip->frag_off));
        printf("ttl: %d\n", ip->ttl);
        printf("protocol: %d\n", ip->protocol);
        printf("check: %04x\n", ntohs(ip->check));
        printf("saddr: %d.%d.%d.%d\n", src[0], src[1], src[2], src[3]);
        printf("daddr: %d.%d.%d.%d\n", dst[0], dst[1],dst[2], dst[3]);
        printf("----------------------------------------\n");

        break;
    }
}
 