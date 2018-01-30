#ifndef CACHE_STRUCTURE_H
#define CACHE_STRUCTURE_H


#define ID_LEN 1


struct cache {
    // DECLARE LIST
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

void add_to_cache(struct cache *c,
                  const unsigned char *pl,
                  int s,
                  unsigned char **hash_val,
                  unsigned char *id);

void __cache_del_entry(struct cache *c);

int get_hitrate(struct cache *c);

int get_saved_traffic_part(struct cache *c);

#endif
