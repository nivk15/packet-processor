#define _GNU_SOURCE
#include <stdio.h>           // printf
#include <stdlib.h>          // exit
#include <string.h>
#include <sys/socket.h>      // socket, recvfrom
#include <netinet/in.h>      // htons
#include <linux/if_ether.h>  // ETH_P_ALL
#include <linux/ip.h>  
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>


//--------------------------------------------------------------------------------
// Part 6  (flow tracking - data structures and functions)
struct flow_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
};

struct flow_stats {
    struct flow_key key;      // which flow is it
    uint64_t packets;         // how many packets
    uint64_t bytes;           // total bytes
    time_t first_seen;        // when the first packet arrived
    time_t last_seen;         // when the latest packet arrived
    int active;               // does flow has been stored here ? 
};

#define TABLE_SIZE 1024
struct flow_stats flow_table[TABLE_SIZE];
int sock;

uint32_t hash_flow(struct flow_key *key) {
    uint32_t hash = key->saddr ^ key->daddr ^ key->sport ^ key->dport ^ key->protocol;
    return hash % TABLE_SIZE;
}


int keys_match(struct flow_key *a, struct flow_key *b) {
    return a->saddr == b->saddr &&
           a->daddr == b->daddr &&
           a->sport == b->sport &&
           a->dport == b->dport &&
           a->protocol == b->protocol;
}


int update_flow(struct flow_key *key, uint32_t packet_size) {
    uint32_t hashed_key = hash_flow(key);

    int i;
    for (i = 0; i < TABLE_SIZE; i++) {
        uint32_t index = (hashed_key + i) % TABLE_SIZE;

        if (!flow_table[index].active) {
            // empty slot -> new flow
            flow_table[index].key = *key;
            flow_table[index].packets = 1;
            flow_table[index].bytes = packet_size;
            time_t t = time(NULL);
            flow_table[index].first_seen = t;
            flow_table[index].last_seen = t;
            flow_table[index].active = 1;
            break;
        }
        if (keys_match(&flow_table[index].key, key)) {
            // same flow 
            flow_table[index].packets += 1;
            flow_table[index].bytes += packet_size;
            flow_table[index].last_seen = time(NULL);
            break;
        }
        // different flow -> try next slot (continue loop)
    }

    return i == TABLE_SIZE ? -1 : 0;
}
//--------------------------------------------------------------------------------


int print_flows(struct flow_stats *table, int max_rows) {
    int count = 0;

    printf("%-25s %-25s %-8s %-8s %-10s %s\n",
           "SRC IP:PORT", "DST IP:PORT", "PROTO", "PKTS", "BYTES", "DURATION");

    for (int i = 0; i < TABLE_SIZE && count < max_rows; i++ ) {
        if (table[i].active) {
            struct flow_key key = table[i].key;
            unsigned char *src = (unsigned char *)&key.saddr;
            unsigned char *dst = (unsigned char *)&key.daddr;
            char proto[16];
            if (key.protocol == 6) strcpy(proto, "TCP");
            else if (key.protocol == 17) strcpy(proto, "UDP");
            else if (key.protocol == 1) strcpy(proto, "ICMP");
            else sprintf(proto, "PROTO(%d)", key.protocol);
            char src_str[32], dst_str[32];

            sprintf(src_str, "%d.%d.%d.%d:%d", src[0], src[1], src[2], src[3], key.sport);
            sprintf(dst_str, "%d.%d.%d.%d:%d", dst[0], dst[1], dst[2], dst[3], key.dport);

            printf("%-25s %-25s %-8s %-8lu %-10lu %.0fs\n",
                src_str, dst_str, proto,
                table[i].packets, table[i].bytes,
                difftime(table[i].last_seen, table[i].first_seen));
            
            count++;
        }
    }
    return count;
}

//--------------------------------------------------------------------------------

void handle_sigint(int sig) {
    printf("\033[H\033[J");   
    int total = print_flows(flow_table, TABLE_SIZE);        // show all the rows
    printf("\n(Total flows tracked: %d)\n", total);
    close(sock);
    exit(0);
}

//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
int main() {

    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);


    // Part 1   (capture raw packets)
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65535];


    while (1){

        int packet_size = recvfrom(sock, buffer, 65535, 0, NULL, NULL);
        if (packet_size == -1) {
            if (errno == EINTR) continue;           // signal interrupted recvfrom, not a real error
            perror("recvfrom");
            return 1;
        }
        //--------------------------------------------------------------------------------

        // Part 2  (parsing Ethernet header)
        struct ethhdr *eth = (struct ethhdr *)buffer;           // grep -A 5 "struct ethhdr" /usr/include/linux/if_ether.h
        
        if (ntohs(eth->h_proto) != 0x0800) continue;           // 0x0800 is the code for IPv4
        //--------------------------------------------------------------------------------

        // Part 3  (parsing IP header)

        struct iphdr *ip = (struct iphdr *)(buffer + 14);           // grep -A 25 "struct iphdr" /usr/include/linux/ip.h

        unsigned char *src = (unsigned char *)&(ip->saddr);
        unsigned char *dst = (unsigned char *)&(ip->daddr);

        // --------------------------------------------------------------------------------

        // Part 4  (parsing TCP & UDP headers to get source and destination ports)
        int sport = 0, dport = 0;
        char proto[16];

        if (ip->protocol == 6) {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + 14 + ip->ihl * 4);      // grep -A 20 "struct tcphdr" /usr/include/linux/tcp.h
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);
            strcpy(proto, "TCP");
        } else if (ip->protocol == 17) {
            struct udphdr *udp = (struct udphdr *)(buffer + 14 + ip->ihl * 4);     // grep -A 10 "struct udphdr" /usr/include/linux/udp.h 
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);
            strcpy(proto, "UDP");
        } else if (ip->protocol == 1) {
            strcpy(proto, "ICMP");
        } else {
            sprintf(proto, "PROTO(%d)", ip->protocol);
        }
        //--------------------------------------------------------------------------------

        // Part 6  (flow tracking - updating)
        struct flow_key key;
        key.saddr = ip->saddr;
        key.daddr = ip->daddr;
        key.sport = sport;
        key.dport = dport;
        key.protocol = ip->protocol;
            
        update_flow(&key, ntohs(ip->tot_len));
        //--------------------------------------------------------------------------------


        // clear screen: * move cursor to top-left:  \033[H   
        //               * erase everything from cursor to end of screen: \033[J 
        printf("\033[H\033[J");   
        print_flows(flow_table, 20);        // show live only 20 rows to work in terminal size window.

    }
}
 