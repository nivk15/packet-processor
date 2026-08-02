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
#include <stdlib.h>
#include <getopt.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "flow.h"

volatile sig_atomic_t got_sigint = 0;

void handle_sigint(int sig) {
    (void)sig;      // sig parameter required by handler signature - here we suppress unused parameter warning
    got_sigint = 1;
}

void print_usage(const char *prog) {
    printf("Usage: %s [-i interface] [-n rows] [-h]\n", prog);
    printf("  -i, --interface   Network interface to capture on (e.g. eth0)\n");
    printf("  -n, --rows        Number of flows to display (default: 20)\n");
    printf("  -h, --help        Show this help message\n");
}

//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
int main(int argc, char *argv[]) {

    char *interface = NULL;
    int rows = 20;

    static struct option long_opts[] = {
        { "interface", required_argument, NULL, 'i' },
        { "rows",      required_argument, NULL, 'n' },
        { "help",      no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:n:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'n': {
                char *end;
                rows = (int)strtol(optarg, &end, 10);
                if (*end != '\0' || rows <= 0) {
                    fprintf(stderr, "Invalid row count: %s\n", optarg);
                    return 1;
                }
                break;
            }
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

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

    if (interface != NULL) {
        struct sockaddr_ll sll = {0};
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = if_nametoindex(interface);
        if (sll.sll_ifindex == 0) {
            fprintf(stderr, "Unknown interface: %s\n", interface);
            close(sock);
            return 1;
        }
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
            perror("bind");
            close(sock);
            return 1;
        }
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
        print_flows(flow_table, rows, 1);       // live view: hide flows that went idle

    }

    printf("\033[H\033[J");
    int total = print_flows(flow_table, TABLE_SIZE, 0);     // summary: show everything captured
    printf("\n(Total flows tracked: %d)\n", total);
    close(sock);
    return 0;
}
 