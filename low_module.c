#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/ip.h>

#include "cache_structure.h"


#define CACHE_SIZE 256

MODULE_LICENSE("GPL");


struct nf_hook_ops bundle;

struct cache *cache;


unsigned int hook_func(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state) {

    struct        iphdr  *iph;
    struct        tcphdr *tcph;
    unsigned int  seq;
    unsigned int  payload_size;
    u16           sport, dport;
    u32           saddr, daddr;
    unsigned char *payload;

    if (!skb) {
        return NF_ACCEPT;
    }

    iph   = ip_hdr(skb);

    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcph  = tcp_hdr(skb);

    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);
    
    if (sport == HTTPS_PORT_NUMBER) {
        return NF_ACCEPT;
    }

    seq   = (unsigned int) htonl(tcph->seq);

    payload_size = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
    payload      = (unsigned char *)
                                 (skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb));
    
    //printk("[Low-Flow-Cache] [DEBUG]: hook_func - Seq to receive - %u\n", seq);
    //printk("[Low-Flow-Cache] [DEBUG]: hook_func - Data size - %d\n",
    //        payload_size);

    if (payload_size == HIT_DATA_LENGTH && segment_is_cashed(tcph)) {
        int iteration,
            flow_index,
            data_offset,
            data_size;

        unsigned char hit_data[HIT_DATA_LENGTH];
        unsigned int  bytes_required;
        char*         token;

        iteration   = 0;
        flow_index  = 0;
        data_offset = 0;
        data_size   = 0;

        memcpy(hit_data, payload, HIT_DATA_LENGTH);

        token   = __strtok((char*) hit_data, " ");
        while (token != NULL) {
            switch(iteration) {
                case 0:
                    sscanf((char*)token, "%d", &flow_index);
                    break;
                case 1:
                    sscanf((char*)token, "%d", &data_offset);
                    break;
                case 2:
                    sscanf((char*)token, "%d", &data_size);
                    break;
            }

            token = __strtok(NULL, " ");
            ++iteration;
        }

        //printk("[Low-Flow-Cache] [DEBUG]: hook_func - Flow: %d, Offset: %d, Size: %d\n",
        //        flow_index,
        //        data_offset,
        //        data_size);

        bytes_required = data_size - HIT_DATA_LENGTH;

        if (!pskb_expand_head(skb, 0, bytes_required, GFP_KERNEL)) {
            struct tcphdr *tcph;
            unsigned char *cached_payload;
            int            len;

            skb_put(skb, bytes_required);
            tcph = tcp_hdr(skb);
            iph  = ip_hdr(skb);

            iph->tot_len = htons((unsigned short)skb->len);

            payload = (unsigned char *)(
                    skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb));

            restore_payload(&cached_payload, flow_index, data_offset, data_size);
            replace_payload(payload, cached_payload, data_size);

            tcph->check = htons(0);
            len         = skb->len - ip_hdrlen(skb);
            tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr,
                                       csum_partial((char*)tcph,
                                       len, 0));
            iph->check  = htons(0);
            iph->check  = ip_fast_csum((unsigned char *)iph, iph->ihl);

            cache->hits++;
            cache->saved_traffic_size += data_size;
            cache->total_traffic_size += data_size;
            print_cache_statistics(cache);

        } else {
            printk("[Low-Flow-Cache] [ERROR]: hook_func - Cannot expand skb!\n");
        }

    } else if (payload_size > 0) {
        if (payload_size >= HTTP_HEADER_FLAG_LENGTH &&
                (payload[0] == 'H' ||
                 payload[1] == 'T' ||
                 payload[2] == 'T' ||
                 payload[3] == 'P' )) {
            return NF_ACCEPT;
        }

        add_to_cache(cache,
             sport,
             saddr,
             dport,
             daddr,
             seq,
             payload,
             payload_size);
    }

    return NF_ACCEPT;
}


int init_func(void) {
    printk("[Low-Flow-Cache] [INFO]: init_func - Initializing new hook\n");

    cache = kmalloc(sizeof(struct cache), GFP_KERNEL);
    init_cache(cache, CACHE_SIZE, true);

    bundle.hook     = hook_func;
    bundle.pf       = PF_INET;
    bundle.hooknum  = NF_INET_PRE_ROUTING;
    bundle.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&bundle);

    return 0;
}


void exit_func(void) {
    //print_cache_data(cache);
    
    print_cache_statistics(cache);
    clean_cache(cache);
    kfree(cache);

    nf_unregister_hook(&bundle);
    printk("[Low-Flow-Cache] [INFO]: exit_func - Exit finished with code 0\n");
}


module_init(init_func);
module_exit(exit_func);
