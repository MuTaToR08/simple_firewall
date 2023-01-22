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


enum RuleMode {
    RULE_ALLOW,
    RULE_DENY
};

struct Rule {
    char* nameProc;
    enum RuleMode mode;
    struct Rule* next;
};

static struct Rule *ruleList = NULL;
static struct Rule *ruleLast = NULL;
static int daemon_pid = 0;
static struct nf_hook_ops nfho;
struct sock *nl_sock = NULL;


void netlink_send_msg(char *msg, int pid, int msg_size) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int res;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
      printk(KERN_ERR "netlink_test: Failed to allocate new skb\n");
      return;
    }

    // put received message into reply
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);
    res = nlmsg_unicast(nl_sock, skb_out, pid);
    if (res < 0)
      printk(KERN_INFO "netlink_test: Error while sending skb to user ret(%d)\n", res);

}


unsigned int hook_func_out(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
 ) {
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *ip = ip_hdr(skb);
    char *msg;
    int size;
    int i;
    struct Rule *rl;

    if(daemon_pid == 0) {
        printk(KERN_INFO "daemon is 0\n");
        return NF_ACCEPT;
    }

    rl = ruleList;

    while (rl != NULL) {
        printk(KERN_INFO "rule %s mode:%d\n", rl->nameProc, rl->mode);
        if(strcmp(current->comm, rl->nameProc) == 0) {
            if(rl->mode == RULE_ALLOW) {
                return NF_ACCEPT;
            }
            if(rl->mode == RULE_DENY) {
                return NF_DROP;
            }
        }
        rl = rl->next;
    }

    size = sizeof (char)*(strlen(current->comm) + 1 + 1 + 4 + 1);
    msg = (char *)kmalloc(sizeof (char) * size, GFP_KERNEL);

    memset(msg, 0, size);
    msg[0] = SEND_TYPE_NEW_RULE;
    strcat(msg, current->comm);
    strcat(msg, "&");
    memcpy(msg+(size-5), (char *)&ip->daddr, sizeof(int));
    msg[size-1] = '\0';
//    printk(KERN_INFO "PACKAGEP SEND %s\n",msg);
    printk(KERN_INFO "IP SEND %pI4 %d\n", &ip->daddr, ip->daddr);

    //    strcat(msg, );
//    printk("%s", sprintf("%pI4", ip->daddr));

    netlink_send_msg(msg, daemon_pid, size);

   // printk("caller: %s\n", current->comm);
   // printk("ma: %pM\n", eth->h_source);
   // printk("ip protocol: %d\n", ip->protocol);
   // printk("%pI4 -> %pI4\n", &ip->saddr, &ip->daddr);
    kfree(msg);
    return NF_ACCEPT;
}

int findAmp(char* str) {
    int len = strlen(str);
    int i;
    for(i=0;i<len;i++){
        if(str[i] == '&') {
            return i;
        }
    }
    return -1;
}

static void netlink_test_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct Rule* rule;
    char *msg;
    int plcAmp;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (char *)nlmsg_data(nlh);
    switch (msg[0]) {
    case NETLINK_OPCODE_HELLO:
        daemon_pid = nlh->nlmsg_pid; /* pid of sending process */
        printk(KERN_INFO "daemon(%d) send HELLO_PACKAGE\n", daemon_pid);
        netlink_send_msg(KERNEL_HELLO, daemon_pid, strlen(KERNEL_HELLO));
        break;
    case NETLINK_OPCODE_RULE:
        plcAmp = findAmp(msg+1);

        rule = (struct Rule*)kmalloc(sizeof (struct Rule), GFP_KERNEL);
        memset(rule, 0, sizeof (struct Rule));
        rule->next = NULL;
        rule->nameProc = (char*) kmalloc(sizeof (char*) * (plcAmp + 1), GFP_KERNEL);
        memset(rule->nameProc, 0, plcAmp + 1);
        strncat(rule->nameProc, msg+1, plcAmp);

        if(strcmp(msg+plcAmp+2, COMMAND_DENY) == 0) {
            rule->mode = RULE_DENY;
        } else {
            rule->mode = RULE_ALLOW;
        }

        if(ruleLast == NULL) {
            ruleList = ruleLast = rule;
        } else {
            ruleLast->next = rule;
            ruleLast = rule;
        }
//*/
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
