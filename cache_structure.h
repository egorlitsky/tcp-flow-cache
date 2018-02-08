#ifndef CACHE_STRUCTURE_H
#define CACHE_STRUCTURE_H


#include "tcp_flow.h"

#define ID_LEN     1
#define KiB        1024
#define PERCENTAGE 100


struct cache {
    long max_size;      // in bytes
    long curr_size;     // in bytes
    int hits;
    int misses;
    long long saved_traffic_size;
    long long total_traffic_size;
};

// cache_size in MB
void init_cache(struct cache *c, int cache_size);

void clean_cache(struct cache *c);

void add_to_cache(struct cache *cache,
        u16 sport,
        u32 saddr,
        u16 dport,
        u32 daddr,
        u16 seq,
        u16 fin,
        const unsigned char *payload,
        int payload_size,
        unsigned char **cache_result,
        unsigned char *id);

void delete_entry_from_cache(struct cache *c);

void print_cache_data(struct cache *c);

int get_hitrate(struct cache *c);

int get_saved_traffic_part(struct cache *c);

#endif
