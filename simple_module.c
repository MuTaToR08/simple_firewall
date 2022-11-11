#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ekaterinka");
MODULE_DESCRIPTION("Diplom work 'Simple Firewall'");

struct stat st = {0};

static struct nf_hook_ops nfho;

unsigned int hook_func_out(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
 ) {
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *ip = ip_hdr(skb);

    printk("caller: %s\n", current->comm);
    printk("ma: %pM\n", eth->h_source);
    printk("ip protocol: %d\n", ip->protocol);
    printk("%pI4 -> %pI4\n", &ip->saddr, &ip->daddr);
    return NF_ACCEPT;
}

static int __init sfw_module_init(void) {
    printk("starting SFW module loading\n");

    int ret = 0;
    struct net *n;

    nfho.hook = hook_func_out;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    for_each_net(n)
        ret += nf_register_net_hook(n, &nfho);

//    if (stat("/etc/simple_firewall", &st) == -1) {
//        mkdir("/etc/simple_firewall", 0700);
//        mkdir("/etc/simple_firewall/ignore", 0700);
//        mkdir("/etc/simple_firewall/store", 0700);
//    }

    printk("nf_register_hook returnd %d\n", ret);
    return 0;
}

static void __exit sfw_module_exit(void)
{
    printk("Remove SFM module\n");

    struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);

}

module_init(sfw_module_init);
module_exit(sfw_module_exit);
