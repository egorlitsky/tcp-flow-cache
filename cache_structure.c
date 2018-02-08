#include "cache_structure.h"
#include <linux/slab.h>

static LIST_HEAD(list_of_flows);


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
        unsigned char *id)
{
    printk("[TCP-Flow-Cache-Module]: add_to_cache - Attempt to find / add packet...\n");
    
    bool flow_found = false;
    
    struct list_head *i;
    list_for_each(i, &list_of_flows) {
        struct tcp_flow *obj = list_entry(i, struct tcp_flow, list);
        
        if (obj->saddr == saddr && obj->daddr == daddr && obj->dport == dport && obj->sport == sport) {
            flow_found = true;
            struct packet *segment = kmalloc(sizeof(*segment), GFP_KERNEL);
            segment->sequence_number = seq;

            add_packet_to_flow(&segment->list, &obj->list_of_packets);
            printk("[TCP-Flow-Cache-Module]: add_to_cache - FOUND AN EXISTING STREAM!\n");
        }
    }
    
    if (!flow_found) {
        struct tcp_flow *flow = kmalloc(sizeof(*flow), GFP_KERNEL);
        flow->saddr = saddr;
        flow->daddr = daddr;
        flow->sport = sport;
        flow->dport = dport;
        flow->size  = 0;

        flow->a_pointer = current;
        list_add(&flow->list, &list_of_flows);

        INIT_LIST_HEAD(&flow->list_of_packets);

        struct packet *segment = kmalloc(sizeof(*segment), GFP_KERNEL);
        segment->sequence_number = seq;
        add_packet_to_flow(&segment->list, &flow->list_of_packets);
        
        printk("[TCP-Flow-Cache-Module]: add_to_cache - NEW FLOW CREATED.\n");
        
    }

    printk("[TCP-Flow-Cache-Module]: add_to_cache - FIN = %d\n", fin);
}

void delete_entry_from_cache(struct cache *c) {
    printk("[TCP-Flow-Cache-Module]: delete_entry_from_cache - Removing cache entry...\n");
}

void init_cache(struct cache *c, int cache_size) {
    c->max_size           = cache_size * KiB * KiB;
    c->curr_size          = 0;
    c->hits               = 0;
    c->misses             = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;
    
    printk("[TCP-Flow-Cache-Module]: init_cache - Cache initialized\n");
}

void clean_cache(struct cache *c) {
    c->curr_size          = 0;
    c->hits               = 0;
    c->misses             = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;
    printk("[TCP-Flow-Cache-Module]: clean_cache - Cache is cleared\n");
}

void print_cache_data(struct cache *c) {
    struct list_head *i;
    list_for_each(i, &list_of_flows) {
        struct tcp_flow *obj = list_entry(i, struct tcp_flow, list);
        printk("\n[TCP-Flow-Cache-Module]: print_cache_data - FLOW - %pI4h:%d -> %pI4h:%d\n",
                &obj->saddr, obj->sport, &obj->daddr, obj->dport);
        
        struct packet *p;
        list_for_each_entry(p, &obj->list_of_packets, list) {
            printk("[TCP-Flow-Cache-Module]: print_cache_data - Packet seq - %u\n", &p->sequence_number);
        }
    }
}

int get_hitrate(struct cache *c) {
    if (c->misses == 0) {
        return 0;
    }

    return PERCENTAGE * c->hits / (c->hits + c->misses);
}

int get_saved_traffic_part(struct cache *c) {
    if (c->total_traffic_size == 0) {
        return 0;
    }

    return PERCENTAGE * c->saved_traffic_size / c->total_traffic_size;
}
