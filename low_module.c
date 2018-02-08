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

struct cache *c;


unsigned int hook_func(const struct nf_hook_ops *ops,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    
    unsigned char *user_data;   /* TCP data begin pointer */
    unsigned char *tail;        /* TCP data end pointer */
    unsigned char *it;          /* TCP data iterator */


    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);

    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
    tail = skb_tail_pointer(skb);

    pr_debug("[Low-Flow-Cache-Module]: hook_func - Route: %pI4h:%d -> %pI4h:%d\n",
            &saddr, sport, &daddr, dport);

    pr_debug("[Low-Flow-Cache-Module]: hook_func - data:\n");
    for (it = user_data; it != tail; ++it) {
        char c = *(char *)it;

        if (c == '\0')
            break;

        printk("%c", c);
    }
    printk("\n\n");

    return NF_ACCEPT;
}


int init_func(void) {
    printk("[Low-Flow-Cache-Module]: init_func - Initializing new hook\n");

    c = kmalloc(sizeof(struct cache), GFP_KERNEL);
    init_cache(c, CACHE_SIZE);

    bundle.hook     = hook_func;
    bundle.pf       = PF_INET;
    bundle.hooknum  = NF_INET_PRE_ROUTING;
    bundle.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&bundle);

    return 0;
}


void exit_func(void) {
    printk("[Low-Flow-Cache-Module]: exit_func - Total hitrate: %d\n",
           get_hitrate(c));
    printk("[Low-Flow-Cache-Module]: exit_func - Saved traffic part: %d\n",
           get_saved_traffic_part(c));

    clean_cache(c);
    kfree(c);

    nf_unregister_hook(&bundle);
    printk("[Low-Flow-Cache-Module]: exit_func - Exit finished with code 0.\n");
}


module_init(init_func);
module_exit(exit_func);
