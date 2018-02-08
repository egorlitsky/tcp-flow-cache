#include <linux/module.h>
#include <linux/kernel.h>
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


unsigned int hook_func(const struct nf_hook_ops *ops,
        struct       sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr  *iph;
    struct tcphdr *tcph;
    u16    sport, dport;
    u32    saddr, daddr;
    u32    seq;
    u16    fin;

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
    
    seq   = ntohl(tcph->seq);
    fin   = tcph->fin;

    unsigned int  payload_size = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
    unsigned char *payload = (unsigned char *)(skb->data + ip_hdrlen(skb) + tcp_hdrlen(skb));
    unsigned char *cache_result,
                  id;
    
    add_to_cache(cache,
                 sport,
                 saddr,
                 dport,
                 daddr,
                 seq,
                 fin,
                 payload,
                 payload_size,
                 &cache_result,
                 &id);
    
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
