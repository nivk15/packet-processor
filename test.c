#include "flow.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int failures = 0;

// prints the failing expression and its line number - no need to write a message per check
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("    line %d: %s\n", __LINE__, #cond);                  \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#define RUN(fn)                                                            \
    do {                                                                   \
        int before = failures;                                             \
        fn();                                                              \
        printf("%s  %s\n", failures == before ? "ok  " : "FAIL", #fn);     \
    } while (0)


// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// flow_table is a global, so every test that touches it starts from a clean slate
static void reset_table(void) {
    memset(flow_table, 0, sizeof(flow_table));
}

static struct flow_key make_key(uint32_t s, uint32_t d, uint16_t sp, uint16_t dp, uint8_t p) {
    struct flow_key k = { .saddr = s, .daddr = d, .sport = sp, .dport = dp, .protocol = p };
    return k;
}

// occupy every slot with a distinct flow
static void fill_table(void) {
    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        struct flow_key k = make_key(i + 1, 1, 1, 1, 6);
        update_flow(&k, 100);
    }
}

static int find_slot(struct flow_key *k) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (flow_table[i].active && keys_match(&flow_table[i].key, k)) return i;
    }
    return -1;
}


// ---------------------------------------------------------------------------
// hash_flow
// ---------------------------------------------------------------------------

static void test_hash_is_deterministic(void) {
    struct flow_key a = make_key(0x0100007F, 0x0200007F, 1234, 80, 6);
    struct flow_key b = a;
    CHECK(hash_flow(&a) == hash_flow(&b));
}

// XOR is commutative, so a hash that just XORs the fields would give the same
// result for A->B and B->A. the per-field multipliers in hash_flow prevent that.
static void test_hash_not_commutative(void) {
    struct flow_key a = make_key(1, 2, 80, 443, 6);
    struct flow_key b = make_key(2, 1, 80, 443, 6);
    CHECK(hash_flow(&a) != hash_flow(&b));
}


// ---------------------------------------------------------------------------
// keys_match
// ---------------------------------------------------------------------------

static void test_keys_match_identical(void) {
    struct flow_key a = make_key(1, 2, 80, 443, 6);
    struct flow_key b = a;
    CHECK(keys_match(&a, &b) == 1);
}

// one field differs per case, so a missing comparison fails exactly one check
// and the output names the field
static void test_keys_match_one_field_differs(void) {
    struct flow_key base = make_key(1, 2, 80, 443, 6);

    struct flow_key saddr_differs    = make_key(9, 2, 80, 443, 6);
    struct flow_key daddr_differs    = make_key(1, 9, 80, 443, 6);
    struct flow_key sport_differs    = make_key(1, 2, 99, 443, 6);
    struct flow_key dport_differs    = make_key(1, 2, 80, 999, 6);
    struct flow_key protocol_differs = make_key(1, 2, 80, 443, 17);

    CHECK(keys_match(&base, &saddr_differs)    == 0);
    CHECK(keys_match(&base, &daddr_differs)    == 0);
    CHECK(keys_match(&base, &sport_differs)    == 0);
    CHECK(keys_match(&base, &dport_differs)    == 0);
    CHECK(keys_match(&base, &protocol_differs) == 0);
}


// ---------------------------------------------------------------------------
// update_flow - basics
// ---------------------------------------------------------------------------

static void test_update_flow_inserts_new(void) {
    reset_table();

    struct flow_key k = make_key(1, 2, 80, 443, 6);
    CHECK(update_flow(&k, 100) == 0);

    int slot = find_slot(&k);
    CHECK(slot != -1);
    CHECK(flow_table[slot].active == 1);
    CHECK(flow_table[slot].packets == 1);
    CHECK(flow_table[slot].bytes == 100);
    CHECK(flow_table[slot].first_seen == flow_table[slot].last_seen);
}

static void test_update_flow_accumulates(void) {
    reset_table();

    struct flow_key k = make_key(1, 2, 80, 443, 6);
    update_flow(&k, 100);
    update_flow(&k, 250);

    int slot = find_slot(&k);
    CHECK(slot != -1);
    CHECK(flow_table[slot].packets == 2);
    CHECK(flow_table[slot].bytes == 350);
}

// the two flows are given different packet counts AND different byte totals, so
// a bug that mixed up their counters cannot pass by coincidence
static void test_update_flow_keeps_flows_separate(void) {
    reset_table();

    struct flow_key a = make_key(1, 2, 80, 443, 6);
    struct flow_key b = make_key(3, 4, 22, 5555, 17);
    update_flow(&a, 150);
    update_flow(&b, 60);
    update_flow(&b, 40);

    int sa = find_slot(&a), sb = find_slot(&b);
    CHECK(sa != -1 && sb != -1);
    CHECK(sa != sb);
    CHECK(flow_table[sa].packets == 1);
    CHECK(flow_table[sa].bytes == 150);
    CHECK(flow_table[sb].packets == 2);
    CHECK(flow_table[sb].bytes == 100);
}


// ---------------------------------------------------------------------------
// update_flow - paths the running program never reaches
// ---------------------------------------------------------------------------

static void test_update_flow_table_full(void) {
    reset_table();
    fill_table();

    // nothing has expired, so there is no slot to take
    struct flow_key extra = make_key(99999, 1, 1, 1, 6);
    CHECK(update_flow(&extra, 100) == -1);
    CHECK(find_slot(&extra) == -1);
}

static void test_update_flow_reuses_expired_slot(void) {
    reset_table();
    fill_table();

    struct flow_key victim = make_key(500, 1, 1, 1, 6);
    int vslot = find_slot(&victim);
    CHECK(vslot != -1);
    flow_table[vslot].last_seen = time(NULL) - (FLOW_TIMEOUT + 10);

    struct flow_key fresh = make_key(99999, 1, 1, 1, 6);
    CHECK(update_flow(&fresh, 42) == 0);

    CHECK(keys_match(&flow_table[vslot].key, &fresh));
    CHECK(flow_table[vslot].packets == 1);
    CHECK(flow_table[vslot].bytes == 42);
}

// two expired flows are available - the one quiet the longest should be taken.
// the expired slots are placed by position along the probe path rather than by
// key, so that first-fit and LRU are forced to disagree: first-fit would stop at
// the nearer slot, LRU has to keep looking and take the farther, older one.
static void test_update_flow_evicts_least_recently_used(void) {
    reset_table();
    fill_table();

    struct flow_key fresh = make_key(99999, 1, 1, 1, 6);
    uint32_t h = hash_flow(&fresh);

    uint32_t near = (h + 1) % TABLE_SIZE;    // met first, went quiet recently
    uint32_t far  = (h + 2) % TABLE_SIZE;    // met second, quiet much longer

    time_t now = time(NULL);
    flow_table[near].last_seen = now - (FLOW_TIMEOUT + 10);
    flow_table[far].last_seen  = now - (FLOW_TIMEOUT + 500);

    struct flow_key near_key = flow_table[near].key;

    CHECK(update_flow(&fresh, 42) == 0);

    CHECK(keys_match(&flow_table[far].key, &fresh));       // oldest taken
    CHECK(keys_match(&flow_table[near].key, &near_key));   // newer one left alone
}

// regression test: expired slots must never be cleared, only overwritten.
// clearing one mid-chain would let a flow further along be re-inserted as new,
// leaving it in the table twice with its stats split.
static void test_expired_slot_does_not_break_probe_chain(void) {
    reset_table();

    struct flow_key a = make_key(1, 2, 80, 443, 6);
    struct flow_key b;

    // ask the hash function for a colliding key instead of hardcoding one, so
    // this keeps testing the collision path if hash_flow ever changes.
    // bounded so a hash change fails loudly rather than hanging.
    int found = 0;
    for (uint32_t i = 2; i < 100000; i++) {
        b = make_key(i, 2, 80, 443, 6);
        if (hash_flow(&b) == hash_flow(&a) && !keys_match(&a, &b)) { found = 1; break; }
    }
    CHECK(found);
    if (!found) return;

    uint32_t h = hash_flow(&a);
    update_flow(&a, 100);      // lands at h
    update_flow(&b, 100);      // collides, probes to h + 1 (table is empty otherwise)

    flow_table[h].last_seen = time(NULL) - (FLOW_TIMEOUT + 10);   // age a out

    update_flow(&b, 50);       // another packet for the flow living past the expired slot

    uint32_t next = (h + 1) % TABLE_SIZE;
    CHECK(keys_match(&flow_table[next].key, &b));
    CHECK(flow_table[next].packets == 2);       // updated in place, not re-inserted
    CHECK(flow_table[next].bytes == 150);
    CHECK(keys_match(&flow_table[h].key, &a));  // expired means reusable, not removed
}


// ---------------------------------------------------------------------------

int main(void) {
    printf("flow table tests\n\n");

    RUN(test_hash_is_deterministic);
    RUN(test_hash_not_commutative);
    RUN(test_keys_match_identical);
    RUN(test_keys_match_one_field_differs);
    RUN(test_update_flow_inserts_new);
    RUN(test_update_flow_accumulates);
    RUN(test_update_flow_keeps_flows_separate);
    RUN(test_update_flow_table_full);
    RUN(test_update_flow_reuses_expired_slot);
    RUN(test_update_flow_evicts_least_recently_used);
    RUN(test_expired_slot_does_not_break_probe_chain);

    if (failures == 0) {
        printf("\nall tests passed\n");
    } else {
        printf("\n%d check(s) failed\n", failures);
    }
    return failures != 0;
}
