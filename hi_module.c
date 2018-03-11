#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/ip.h>

#include "cache_structure.h"


#define CACHE_SIZE        256
#define HIT_DATA_LENGTH   10

MODULE_LICENSE("GPL");

struct nf_hook_ops bundle;

struct cache *cache;

void replace_payload(unsigned char *payload, const unsigned char *hit_data) {
    memcpy(payload, hit_data, HIT_DATA_LENGTH);
    // TODO: decide about RES bits
}

unsigned int hook_func(const struct nf_hook_ops *ops,
        struct       sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct       iphdr  *iph;
    struct       tcphdr *tcph;
    u16          sport, dport;
    u32          saddr, daddr;
    u16          fin;
    unsigned int seq;

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
    
    seq   = (unsigned int) htonl(tcph->seq);
    fin   = tcph->fin;
    
    unsigned int  payload_size = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
    unsigned char *payload = (unsigned char *)(
                                skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb));
    
    if (payload_size > 0) {
        struct hit_data* cache_result;
        cache_result = add_to_cache(cache,
                     sport,
                     saddr,
                     dport,
                     daddr,
                     fin,
                     seq,
                     payload,
                     payload_size);
    
        if (cache_result->flow_index != NOT_FOUND) {
            
            // TODO: decide about RES bits, choose a format of hit_data
            
            /*
            skb_trim(skb, ip_hdrlen(skb) + tcp_hdrlen(skb) + HIT_DATA_LENGTH);
            iph->tot_len = htons((unsigned short)skb->len);
            unsigned char data[] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
            replace_payload(payload, data);
            tcph->check = htons(0);
            int len = skb->len - ip_hdrlen(skb);
            tcph->check = tcp_v4_check(len,
                                       iph->saddr,
                                       iph->daddr,
                                       csum_partial((char*)tcph, len, 0));
            iph->check = htons(0);
            iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
            */
        }
        kfree(cache_result);
    }
    
    return NF_ACCEPT;
}


int init_func(void) {
    printk("[High-Flow-Cache-Module]: init_func - Initializing new hook\n");

    cache = kmalloc(sizeof(struct cache), GFP_KERNEL);
    init_cache(cache, CACHE_SIZE);

    bundle.hook     = hook_func;
    bundle.pf       = PF_INET;
    bundle.hooknum  = NF_INET_POST_ROUTING;
    bundle.priority = NF_IP_PRI_LAST;

    nf_register_hook(&bundle);

    return 0;
}


void exit_func(void) {
    print_cache_data(cache);
    
    printk("[High-Flow-Cache-Module]: exit_func - Total hitrate: %d\n",
           get_hitrate(cache));
    printk("[High-Flow-Cache-Module]: exit_func - Saved traffic part: %d\n",
           get_saved_traffic_part(cache));

    clean_cache(cache);
    kfree(cache);

    nf_unregister_hook(&bundle);
    printk("[High-Flow-Cache-Module]: exit_func - Exit finished with code 0.\n");
}


module_init(init_func);
module_exit(exit_func);
