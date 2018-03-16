#include "cache_utilities.h"

char *__strtok(char * str, const char * delim)
{
    static char* p = 0;
    
    if(str) {
        p = str;
    } else if(!p) {
        return 0;
    }
    
    str = p   + strspn(p,delim);
    p   = str + strcspn(str,delim);
    
    if(p == str) {
        return p = 0;
    }
    p = *p ? *p = 0, p + 1 : 0;
    
    return str;
}

void replace_payload(unsigned char *payload, const unsigned char *hit_data,
        int new_payload_size) {
    
    memcpy(payload, hit_data, new_payload_size);
}

void adjust_tcp_res_bits(struct tcphdr *tcph, int is_hit) {
    tcph->res1 &= 1 + (1 << 3);
    tcph->res1 |= (is_hit == IS_HIT ? 1 : 0) << HIT_FLAG_BITNUM;
}

unsigned char segment_is_cashed(const struct tcphdr *tcph) {
    unsigned char result;
    result = tcph->res1 & (1 << HIT_FLAG_BITNUM);
    return result;
}

