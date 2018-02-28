#ifndef TCP_FLOW_H
#define TCP_FLOW_H


#include <linux/kernel.h>
#include <linux/list.h>

struct tcp_flow {
    struct list_head list;
    u16 sport, dport;
    u32 saddr, daddr;
    struct list_head list_of_packets;
    unsigned char *data;
    bool data_ready;
    int size;
    void *a_pointer;
};

struct packet {
    struct list_head list;
    unsigned int sequence_number;
    const unsigned char *payload;
    unsigned int payload_size;
};

struct hit_data {
    int flow_index;
    int data_offset;
    int data_size;
};

int get_size(struct tcp_flow *flow);

void add_packet_to_flow(struct list_head *new, struct list_head *head);

#endif

