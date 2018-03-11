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
        
        // TODO: increase traffic part
        ++cache->hits;
        
    } else {
        
        // TODO: increase traffic part
        ++cache->misses;

        printk("[TCP-Flow-Cache-Module]: add_to_cache - Attempt to add packet...\n");
        
        bool flow_found = false;
        struct list_head *i;
        
        list_for_each(i, &list_of_flows) {
            struct tcp_flow *obj = list_entry(i, struct tcp_flow, list);

            if (obj->saddr == saddr && obj->daddr == daddr && obj->dport == dport && obj->sport == sport) {
                flow_found = true;
                printk("[TCP-Flow-Cache-Module]: add_to_cache - An existing flow has been found\n");
                
                struct packet *segment = kmalloc(sizeof(struct packet), GFP_KERNEL);
                segment->sequence_number = seq;
                segment->payload = payload;
                segment->payload_size = payload_size;

                add_packet_to_flow(&segment->list, &obj->list_of_packets);
                obj->size += payload_size;
            }
        }

        if (!flow_found) {
            struct tcp_flow *flow = kmalloc(sizeof(struct tcp_flow), GFP_KERNEL);
            flow->saddr = saddr;
            flow->daddr = daddr;
            flow->sport = sport;
            flow->dport = dport;
            flow->size  = 0;
            flow->data_ready = false;

            flow->a_pointer = current;
            list_add(&flow->list, &list_of_flows);

            INIT_LIST_HEAD(&flow->list_of_packets);

            struct packet *segment = kmalloc(sizeof(struct packet), GFP_KERNEL);
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

int u_strstr(struct tcp_flow *flow, unsigned char *payload, int payload_size)
{
    if (flow->size == 0 || payload == NULL || payload_size <= 0) {
        return NOT_FOUND;
    }

    int  i                    =  0;
    int  j                    =  0;
    int  payload_index        =  0;
    int  offset               =  0;
    int  current_packet_index =  0;
    int  found_packet_index   =  0;
    bool found                =  false;
    bool compares             =  false;
    
    struct packet *p;
    list_for_each_entry(p, &flow->list_of_packets, list) {
        for (i = 0; i < p->payload_size; ++i) {
            if ((!compares && p->payload[i] == payload[0]) || compares) {
                compares = true;
                
                for (j = i; j < p->payload_size; ++j) {
                    if (p->payload[j] == payload[payload_index]) {
                        compares = true;
                        payload_index++;
                        
                        if (payload_index == payload_size) {
                            found              = true;
                            offset             = j + 1;
                            found_packet_index = current_packet_index;                            
                            break;
                        }
                        continue;
                        
                    } else {
                        payload_index = 0;
                        compares      = false;
                    }
                }
                if (compares) {
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (found) {
            break;
        }
        
        ++current_packet_index;
    }
    
    if (found) {
        current_packet_index = 0;
        list_for_each_entry(p, &flow->list_of_packets, list) {
            if (current_packet_index == found_packet_index) {
                break;
            } else {
                offset += p->payload_size;
            }
            
            ++current_packet_index;
        }
        
        offset -= payload_size;
        return offset;
    } else {
        return NOT_FOUND;
    }
}

struct hit_data* find_payload(unsigned char *payload, int payload_size) {
    struct list_head *fl;
    struct hit_data  *h_data;

    int flow_index =  0;
    int offset     =  NOT_FOUND;
    
    printk("[TCP-Flow-Cache-Module]: find_payload - Searching segment...\n");
    
    list_for_each(fl, &list_of_flows) {
        struct tcp_flow *flow = list_entry(fl, struct tcp_flow, list);

        // search just in TCP flows having the data
        if (flow->size > 0) {
            offset = u_strstr(flow, payload, payload_size);

            if (offset != NOT_FOUND) {
                printk("[TCP-Flow-Cache-Module]: find_payload - The segment has been found in cache!\n");
                printk("[TCP-Flow-Cache-Module]: find_payload - Flow: %d, offset: %d\n", flow_index, offset);

                h_data = kmalloc(sizeof(struct hit_data), GFP_KERNEL);
                h_data->flow_index  = flow_index;
                h_data->data_offset = offset;
                h_data->data_size   = payload_size;
                return h_data;
            }
        }
        ++flow_index;
    }
    
    h_data = kmalloc(sizeof(struct hit_data), GFP_KERNEL);
    h_data->flow_index  = NOT_FOUND;
    h_data->data_offset = NOT_FOUND;
    h_data->data_size   = NOT_FOUND;
    return h_data;
}

void delete_entry_from_cache(struct cache *c) {
    // TODO: implement
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
    // TODO: clear list of flows and lists of packets
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
