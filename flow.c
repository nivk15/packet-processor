#include "flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct flow_stats flow_table[TABLE_SIZE];

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

int compar(const void *a, const void *b) {
    struct flow_stats *p_flow_A = (struct flow_stats *)a;
    struct flow_stats *p_flow_B = (struct flow_stats *)b;

    uint64_t bytes_A = p_flow_A->bytes;
    uint64_t bytes_B = p_flow_B->bytes;

    if (bytes_A < bytes_B) {
        return 1;
    } else if (bytes_A == bytes_B) {
        return 0;
    } else return -1;
}

int print_flows(struct flow_stats *table, int limit) {
    printf("%-25s %-25s %-8s %-8s %-10s %s\n",
           "SRC IP:PORT", "DST IP:PORT", "PROTO", "PKTS", "BYTES", "DURATION");

    struct flow_stats active[TABLE_SIZE];
    int n = 0;
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (table[i].active) {
            active[n++] = table[i];
        }
    }

    qsort(active, n, sizeof(struct flow_stats), compar);
    limit = (n < limit) ? n : limit;

    for (int i = 0; i < limit; i++) {
        struct flow_key key = active[i].key;
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
            active[i].packets, active[i].bytes,
            difftime(active[i].last_seen, active[i].first_seen));
    }
    return limit;
}
