#ifndef COMMON_H
#define COMMON_H

#define SEND_TYPE_EXIT       2
#define SEND_TYPE_NEW_RULE   3
#define RECIVE_TYPE_NEW_RULE   3
#define NETLINK_TRANSFER_ID  17
#define MAX_PAYLOAD 1024  /* maximum payload size */

#define KERNEL_HELLO "\1kHello"
#define DAEMON_HELLO "\1Hello"
#define KERNEL_EXIT "\2kExit"
#define DAEMON_EXIT "\2Exit"

#define PATH_ROOT "/etc/simpleFirewall"
#define PATH_CONFIG "/etc/simpleFirewall/config"

#define COMMAND_DENY "deny"
#define COMMAND_ALLOW "allow"


#define NETLINK_OPCODE_HELLO 1
#define NETLINK_OPCODE_RULE 4
#endif // COMMON_H
