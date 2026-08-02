#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <time.h>

#define TABLE_SIZE 1024
#define FLOW_TIMEOUT 30       // seconds of silence before a flow is considered dead

struct flow_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
};

struct flow_stats {
    struct flow_key key;      // which flow
    uint64_t packets;         // how many packets
    uint64_t bytes;           // total bytes
    time_t first_seen;        // when the first packet arrived
    time_t last_seen;         // when the latest packet arrived
    int active;               // is this slot occupied?
};

extern struct flow_stats flow_table[TABLE_SIZE];

uint32_t hash_flow(struct flow_key *key);
int keys_match(struct flow_key *a, struct flow_key *b);
int flow_expired(struct flow_stats *f, time_t now);
int update_flow(struct flow_key *key, uint32_t packet_size);
int compar(const void *a, const void *b);
int print_flows(struct flow_stats *table, int limit, int hide_expired);

#endif
