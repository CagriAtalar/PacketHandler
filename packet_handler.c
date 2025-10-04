#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;

unsigned int hook_func(void *priv,
                       struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
    struct iphdr *ip = ip_hdr(skb);
    if (ip) {
        printk(KERN_INFO "Packet caught: src=%pI4 dst=%pI4 proto=%d\n",
               &ip->saddr, &ip->daddr, ip->protocol);
    }
    return NF_ACCEPT; // paketi geçir
}

static int __init start(void) {
    nfho.hook = hook_func;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING; // en başta yakala
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Netfilter module loaded\n");
    return 0;
}

static void __exit stop(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(start);
module_exit(stop);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cagri Atalar");
