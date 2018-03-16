#ifndef UTILS_H
#define UTILS_H

#include <linux/string.h>
#include <uapi/linux/tcp.h>

#define NOT_FOUND        -1
#define HIT_DATA_LENGTH   25
#define IS_HIT            1
#define HIT_FLAG_BITNUM   1

char *__strtok(char * str, const char * delim);

void adjust_tcp_res_bits(struct tcphdr *tcph, int is_hit);

void replace_payload(unsigned char *payload, const unsigned char *hit_data,
        int new_payload_size);

unsigned char segment_is_cashed(const struct tcphdr *tcph);

#endif

