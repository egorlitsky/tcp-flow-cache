#include "cache_structure.h"
#include <linux/slab.h>


struct ht_entry {
    unsigned char packets_num;
    struct hlist_head packets_list;
};


struct data_entry {
    unsigned char id;
};


void __cache_del_entry(struct cache *c) {
    printk("[TCP-Flow-Cache-Module]: __cache_del_entry\n");
}


void add_to_cache(struct cache *c,
                  const unsigned char *pl,
                  int s,
                  unsigned char **hash_val,
                  unsigned char *id)
{
    printk("[TCP-Flow-Cache-Module]: add_to_cache\n");
}

void init_cache(struct cache *c, int cache_size) {
    c->max_size = cache_size * 1024 * 1024;
    c->curr_size = 0;
    c->hits = 0;
    c->misses = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;
    
    // TODO: init data structure
    printk("[TCP-Flow-Cache-Module]: init_cache\n");
}

void clean_cache(struct cache *c) {
    // TODO: clean data structure
    
    c->curr_size = 0;
    c->hits = 0;
    c->misses = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;
    printk("[TCP-Flow-Cache-Module]: clean_cache\n");
}

int get_hitrate(struct cache *c) {
    if (c->misses == 0)
        return 0;

    return 100 * c->hits / (c->hits + c->misses);
}

int get_saved_traffic_part(struct cache *c) {
    if (c->total_traffic_size == 0)
        return 0;

    return 100 * c->saved_traffic_size / c->total_traffic_size;
}
