#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/sched.h> // for for_each_process

#include "common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ekaterinka");
MODULE_DESCRIPTION("Diplom work 'Simple Firewall'");

static struct nf_hook_ops nfho;
static int daemon_pid = 0;
static struct task_struct *ke_thread;
struct sock *nl_sock = NULL;


void netlink_send_msg(char *msg, int pid) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int res;
    // create reply
    int msg_size = strlen(msg);
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
      printk(KERN_ERR "netlink_test: Failed to allocate new skb\n");
      return;
    }

    // put received message into reply
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    printk(KERN_INFO "netlink_test: Send %s\n", msg);

    res = nlmsg_unicast(nl_sock, skb_out, pid);
    if (res < 0)
      printk(KERN_INFO "netlink_test: Error while sending skb to user\n");

}


unsigned int hook_func_out(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
 ) {
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *ip = ip_hdr(skb);
    char msg[100];
    if(daemon_pid == 0) {
        return NF_ACCEPT;
    }

    strcat(msg, current->comm);
    strcat(msg, "&");
    strcat(msg, sprintf("%pI4", ip->daddr));


    printk(KERN_INFO "netlink_test: Received to pid %d: %s\n", daemon_pid, msg);
    netlink_send_msg(msg, daemon_pid);


   // printk("caller: %s\n", current->comm);
   // printk("ma: %pM\n", eth->h_source);
   // printk("ip protocol: %d\n", ip->protocol);
   // printk("%pI4 -> %pI4\n", &ip->saddr, &ip->daddr);
    return NF_ACCEPT;
}

static void netlink_test_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    char *msg;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (char *)nlmsg_data(nlh);
    switch (msg[0]) {
    case NETLINK_OPCODE_HELLO:
        daemon_pid = nlh->nlmsg_pid; /* pid of sending process */
        printk(KERN_INFO "daemon(%d) say \"hello\"\n", daemon_pid);
        netlink_send_msg("kernel hello", daemon_pid);
        break;
    }

    printk(KERN_INFO "netlink_test: Received from pid %d: %s\n", daemon_pid, msg);
}

static int __init sfw_module_init(void) {
    printk("starting SFW module loading\n");

    int ret = 0;
    struct net *n;
    struct netlink_kernel_cfg cfg = {
      .input = netlink_test_recv_msg,
    };
    struct task_struct *task_list;

    /*
    for_each_process(task_list) {
        if(strcmp(task_list->comm, "sfw_daemon") == 0){
            daemon_pid = task_list->pid;
        }
    }

    if(daemon_pid == 0) {
        printk(KERN_ALERT "sfw: daemon not found \n");
        return -1;
    } */

    nfho.hook = hook_func_out;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    for_each_net(n) {
        ret += nf_register_net_hook(n, &nfho);
    }        

    nl_sock = netlink_kernel_create(&init_net, NETLINK_TRANSFER_ID, &cfg);
    if (!nl_sock) {
      printk(KERN_ALERT "netlink_test: Error creating socket.\n");
      ret = -10;
    }

    if(ret != 0){
        for_each_net(n)
            nf_unregister_net_hook(n, &nfho);

        netlink_kernel_release(nl_sock);
    }

    return ret;
}

static void __exit sfw_module_exit(void)
{
    printk("Remove SFM module\n");

    struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);

    netlink_kernel_release(nl_sock);
}

module_init(sfw_module_init);
module_exit(sfw_module_exit);
