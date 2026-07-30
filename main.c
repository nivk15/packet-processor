#define _GNU_SOURCE
#include <stdio.h>           // printf
#include <sys/socket.h>      // socket, recvfrom
#include <netinet/in.h>      // htons
#include <linux/if_ether.h>  // ETH_P_ALL
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "flow.h"

volatile sig_atomic_t got_sigint = 0;

void handle_sigint(int sig) {
    (void)sig;      // sig parameter required by handler signature - here we suppress unused parameter warning
    got_sigint = 1;
}


//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
int main() {

    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);


    //   (capture raw packets)
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65535];


    while (1){

        int packet_size = recvfrom(sock, buffer, 65535, 0, NULL, NULL);
        if (packet_size == -1) {
            if (errno == EINTR) { 
                if (got_sigint) break;
                continue; 
            }
            perror("recvfrom");
            return 1;
        }
        //--------------------------------------------------------------------------------
        //   (parsing Ethernet header)
        if ((size_t)packet_size < ETH_HLEN) continue;     // too short for Ethernet header

        struct ethhdr *eth = (struct ethhdr *)buffer;           // grep -A 5 "struct ethhdr" /usr/include/linux/if_ether.h

        //--------------------------------------------------------------------------------
        if (ntohs(eth->h_proto) != 0x0800) continue;           // 0x0800 is the code for IPv4
        //--------------------------------------------------------------------------------

        //   (parsing IP header)
        if ((size_t)packet_size < ETH_HLEN + sizeof(struct iphdr)) continue;       // too short for IP header

        struct iphdr *ip = (struct iphdr *)(buffer + ETH_HLEN);           // grep -A 25 "struct iphdr" /usr/include/linux/ip.h

        // --------------------------------------------------------------------------------

        //  (parsing TCP & UDP headers to get source and destination ports)

        int sport = 0, dport = 0;
        char proto[16];
        int ip_header_len = ip->ihl * 4;

        if (ip->protocol == 6) {
            if ((size_t)packet_size < ETH_HLEN + ip_header_len + sizeof(struct tcphdr)) continue;  // too short for TCP header
            struct tcphdr *tcp = (struct tcphdr *)(buffer + ETH_HLEN + ip_header_len);      // grep -A 20 "struct tcphdr" /usr/include/linux/tcp.h
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);
            strcpy(proto, "TCP");
        } else if (ip->protocol == 17) {
            if ((size_t)packet_size < ETH_HLEN + ip_header_len + sizeof(struct udphdr)) continue;  // too short for UDP header
            struct udphdr *udp = (struct udphdr *)(buffer + ETH_HLEN + ip_header_len);     // grep -A 10 "struct udphdr" /usr/include/linux/udp.h 
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);
            strcpy(proto, "UDP");
        } else if (ip->protocol == 1) {
            strcpy(proto, "ICMP");
        } else {
            sprintf(proto, "PROTO(%d)", ip->protocol);
        }
        //--------------------------------------------------------------------------------

        // (flow tracking - updating)
        struct flow_key key;
        key.saddr = ip->saddr;
        key.daddr = ip->daddr;
        key.sport = sport;
        key.dport = dport;
        key.protocol = ip->protocol;
            
        if (update_flow(&key, ntohs(ip->tot_len)) == -1) {
            fprintf(stderr, "Flow table full, not adding the packet.\n");
        }
        //--------------------------------------------------------------------------------


        // clear screen: * move cursor to top-left:  \033[H   
        //               * erase everything from cursor to end of screen: \033[J 
        printf("\033[H\033[J");   
        print_flows(flow_table, 20);        // show live only 20 rows to work in terminal size window.

    }

    printf("\033[H\033[J");
    int total = print_flows(flow_table, TABLE_SIZE);
    printf("\n(Total flows tracked: %d)\n", total);
    close(sock);
    return 0;
}
 