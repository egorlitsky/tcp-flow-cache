#include "cache_structure.h"
#include <linux/slab.h>
#include <linux/string.h>

static LIST_HEAD(list_of_flows);


void add_to_cache(struct cache *cache,
        u16                 sport,
        u32                 saddr,
        u16                 dport,
        u32                 daddr,
        u16                 fin,
        unsigned int        seq,
        const unsigned char *payload,
        int                 payload_size,
        unsigned char       **cache_result,
        unsigned char       *id)
{
    bool search_result = find_payload(payload, payload_size);
    
    if (search_result) {
        
        // TODO: increase counters, return HitData
        
    } else {
        
        printk("[TCP-Flow-Cache-Module]: add_to_cache - Attempt to add packet...\n");
        
        bool flow_found = false;
        struct list_head *i;
        
        list_for_each(i, &list_of_flows) {
            struct tcp_flow *obj = list_entry(i, struct tcp_flow, list);

            if (obj->saddr == saddr && obj->daddr == daddr && obj->dport == dport && obj->sport == sport) {
                flow_found = true;
                printk("[TCP-Flow-Cache-Module]: add_to_cache - An existing flow has been found\n");
                
                struct packet *segment = kmalloc(sizeof(*segment), GFP_KERNEL);
                segment->sequence_number = seq;
                segment->payload = payload;
                segment->payload_size = payload_size;

                add_packet_to_flow(&segment->list, &obj->list_of_packets);
                obj->size += payload_size;

                // flow is closed, we can build common string with all segments
                if (fin) {
                    obj->data = kmalloc(obj->size, GFP_KERNEL);
                    printk("[TCP-Flow-Cache-Module]: add_to_cache - Memory is allocated for flow data\n");

                    int next_segment_offset = 0;
                    struct packet *p;
                    
                    list_for_each_entry(p, &obj->list_of_packets, list) {
                        memcpy(obj->data + next_segment_offset, p->payload, p->payload_size);
                        next_segment_offset += p->payload_size;
                    }

                    obj->data_ready = true;
                    printk("[TCP-Flow-Cache-Module]: add_to_cache - Flow is ready.\n");
                }
            }
        }

        if (!flow_found) {
            struct tcp_flow *flow = kmalloc(sizeof(*flow), GFP_KERNEL);
            flow->saddr = saddr;
            flow->daddr = daddr;
            flow->sport = sport;
            flow->dport = dport;
            flow->size  = 0;
            flow->data_ready = false;

            flow->a_pointer = current;
            list_add(&flow->list, &list_of_flows);

            INIT_LIST_HEAD(&flow->list_of_packets);

            struct packet *segment = kmalloc(sizeof(*segment), GFP_KERNEL);
            segment->sequence_number = seq;
            segment->payload = payload;
            segment->payload_size = payload_size;
            
            add_packet_to_flow(&segment->list, &flow->list_of_packets);
            flow->size += payload_size;

            printk("[TCP-Flow-Cache-Module]: add_to_cache - New flow created!.\n");
        }

        printk("[TCP-Flow-Cache-Module]: add_to_cache - FIN = %d\n", fin);
    }
}

bool find_payload(unsigned char *payload, int payload_size) {
    
    printk("[TCP-Flow-Cache-Module]: find_payload - Searching segment...\n");
    
    struct list_head *fl;
    list_for_each(fl, &list_of_flows) {
        struct tcp_flow *flow = list_entry(fl, struct tcp_flow, list);
        
        // search just in ready (finished) TCP flows
        if (flow->data_ready) {
            if (strstr((char*) flow->data, (char*) payload) != NULL) {
                printk("[TCP-Flow-Cache-Module]: find_payload - The segment has been found in cache!\n");
                return true;
            }
        }
    }
    
    return false;
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
            printk("[TCP-Flow-Cache-Module]: print_cache_data - Segment seq - %u\n", p->sequence_number);
            print_payload(p->payload, p->payload_size, p->sequence_number);
        }
    }
}

void print_payload(const unsigned char *payload,
                   int payload_size,
                   unsigned int seq) {
    
    printk("[TCP-Flow-Cache-Module]: print_payload - Printing payload of segment %u:\n\n", seq);
    
    int  i = 0;
    for (i = 0; i < payload_size; ++i) {
        char c = (char) payload[i];

        if (c == '\0')
            break;

        char wiresharkChar = c >= ' ' && c < 0x7f ? c : '.';

        if (c == '\n' || c == '\r' || c == '\t') {
            printk("%c", c);
        } else {
            printk("%c", wiresharkChar);
        }
    }
    printk("\n\n");
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
