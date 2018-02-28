#include "cache_structure.h"
#include <linux/slab.h>
#include <linux/string.h>

static LIST_HEAD(list_of_flows);


struct hit_data* add_to_cache(struct cache *cache,
        u16                 sport,
        u32                 saddr,
        u16                 dport,
        u32                 daddr,
        u16                 fin,
        unsigned int        seq,
        const unsigned char *payload,
        int                 payload_size)
{
    struct hit_data* search_result;
    search_result = find_payload(payload, payload_size);
    
    if (search_result->data_offset != NOT_FOUND) {
        
        ++cache->hits;
        
    } else {
        
        ++cache->misses;

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

                // TODO: decide, use FIN or not
                // if (fin) {
                if (obj->size) {
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

            printk("[TCP-Flow-Cache-Module]: add_to_cache - New flow created.\n");
        }

        printk("[TCP-Flow-Cache-Module]: add_to_cache - FIN = %d\n", fin);
    }

    return search_result;
}

unsigned char* u_strstr(unsigned char *string, unsigned char *pattern)
{
    int i, j;
    int flag = 0;

    if ((string == NULL || pattern == NULL)) {
        return NULL;
    }

    for( i = 0; string[i] != '\0'; ++i) {
        if (string[i] == pattern[0]) {

            for (j = i; ; j++) {
                if (pattern[j - i] == '\0') {
                    flag = 1; break;
                }

                if (string[j] == pattern[j - i]) {
                    continue;
                } else {
                    break;
                }
            }
        }

        if (flag == 1) {
            break;
        }
    }

    if (flag) {
        return (string + i);
    } else {
        return NULL;
    }
}

struct hit_data* find_payload(unsigned char *payload, int payload_size) {
    struct list_head *fl;
    struct hit_data  *h_data;
    unsigned char    *result;

    int flow_index =  0;
    int offset     =  NOT_FOUND;
    
    printk("[TCP-Flow-Cache-Module]: find_payload - Searching segment...\n");
    
    list_for_each(fl, &list_of_flows) {
        struct tcp_flow *flow = list_entry(fl, struct tcp_flow, list);

        // search just in ready TCP flows
        if (flow->data_ready) {
            result = u_strstr(flow->data, payload);

            if (result) {
                offset = result - flow->data;
                printk("[TCP-Flow-Cache-Module]: find_payload - The segment has been found in cache!\n");
                printk("[TCP-Flow-Cache-Module]: find_payload - Flow: %d, offset: %d\n", flow_index, offset);

                h_data = kmalloc(sizeof(*h_data), GFP_KERNEL);
                h_data->flow_index  = flow_index;
                h_data->data_offset = offset;
                h_data->data_size   = payload_size;
                return h_data;
            }
        }
        ++flow_index;
    }
    
    h_data = kmalloc(sizeof(*h_data), GFP_KERNEL);
    h_data->flow_index  = NOT_FOUND;
    h_data->data_offset = NOT_FOUND;
    h_data->data_size   = NOT_FOUND;
    return h_data;
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
    
    int  i;
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
