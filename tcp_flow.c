#include "tcp_flow.h"

int get_size(struct tcp_flow *flow) {
    return flow->size;
}

void add_packet_to_flow(struct list_head *new, struct list_head *head) {
    list_add_tail(new, head);
}

