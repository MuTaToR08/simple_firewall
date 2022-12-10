/*
 * daemonize.c
 * This example daemonizes a process, writes a few log messages,
 * sleeps 20 seconds and terminates afterwards.
 * This is an answer to the stackoverflow question:
 * https://stackoverflow.com/questions/17954432/creating-a-daemon-in-linux/17955149#17955149
 * Fork this code: https://github.com/pasce/daemon-skeleton-linux-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <string.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <sys/socket.h>
#include <errno.h>


#include "common.h"

static void skeleton_daemon()
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }

    /* Open the log file */
    openlog ("firstdaemon", LOG_PID, LOG_DAEMON);
}

int create_socket() {
    int sock_fd;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TRANSFER_ID);
    if (sock_fd < 0) {
      syslog(LOG_NOTICE, "socket: \n");
    }

    return sock_fd;
}

int bind_socket(int sock_fd) {
    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    src_addr.nl_groups = 0;  /* not in mcast groups */
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

}

char * reciv_data(int sock_fd) {
    struct nlmsghdr *nlh;
    int rc;
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_nl dest_addr;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;


    syslog(LOG_NOTICE, "wait recive\n");
    rc = recvmsg(sock_fd, &msg, 0);
    syslog(LOG_NOTICE, "recived\n");
    if (rc < 0) {
      syslog(LOG_NOTICE, "sendmsg(): %s\n");
      close(sock_fd);
      return NULL;
    }

    return NLMSG_DATA(nlh);
}

int send_data(int sock_fd, char *send) {
    struct sockaddr_nl dest_addr;
    struct nlmsghdr *nlh;
    struct msghdr msg;
    struct iovec iov;
    int rc;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));

    /* Fill the netlink message header */
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();  /* self pid */
    nlh->nlmsg_flags = 0;

    /* Fill in the netlink message payload */
    strcpy(NLMSG_DATA(nlh), send);

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    syslog(LOG_NOTICE,"Send to kernel: %s\n", send);

    rc = sendmsg(sock_fd, &msg, 0);
    if (rc < 0) {
      syslog(LOG_NOTICE, "sendmsg(): \n");
      close(sock_fd);
      return 1;
    }

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    rc = recvmsg(sock_fd, &msg, 0);
    if (rc < 0) {
      syslog(LOG_NOTICE,"sendmsg(): \n");
    //  close(sock_fd);
    //  return 1;
    }

    syslog(LOG_NOTICE, "Received from kernel in send: %s\n", NLMSG_DATA(nlh));

    return 0;
}

int main()
{
    skeleton_daemon();

    char *data;
    unsigned nbytes;

    int sock_fd;
    int rc;

    sock_fd = create_socket();

    send_data(sock_fd, "\1Hello");

   // data = reciv_data(sock_fd);
/*

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   /* For Linux Kernel */
   // dest_addr.nl_groups = 0; /* unicast */


    /* Read message from kernel */
   // memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

   // rc = recvmsg(sock_fd, &msg, 0);
   // if (rc < 0) {
     // printf("sendmsg(): %s\n", strerror(errno));
    //  close(sock_fd);
    //  return 1;
   // }

    syslog (LOG_NOTICE, "Received from kernel: \n"); //NLMSG_DATA(nlh));

    /* Close Netlink Socket */
//    close(sock_fd);

    
    //for( ;; ) {
       //   pid = Receive( 0, &msg, sizeof( msg ) );
       //   nbytes = sizeof( msg.status );
       //   syslog (LOG_NOTICE, "get message from SEND.");
       //   Reply( pid, 0, 0 );
   // }


    syslog (LOG_NOTICE, "First daemon terminated.");
    closelog();

    return EXIT_SUCCESS;
}
