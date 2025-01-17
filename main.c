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
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>


struct stat st = {0};

#include "common.h"

void load_KE() {
    if(system("insmod simple_module.ko") == 0) {
        syslog(LOG_NOTICE, "module loaded: \n");
    }else {
        syslog(LOG_NOTICE, "module notLoaded: \n");
    }
}

void unload_KE() {
    if(system("rmmod simple_module.ko") == 0) {
        syslog(LOG_NOTICE, "module unloaded: \n");
    }
}

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

struct ReciveMsg {
    char* msg;
    int length;
};

struct ArgPthread {
    char *comm;
    char *ip;
    int socke_fd;
};

struct ReciveMsg * reciv_data(int sock_fd) {
    struct nlmsghdr *nlh;
    struct msghdr msg;
    struct iovec iov;
    int rc;
    struct ReciveMsg* recive;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    rc = recvmsg(sock_fd, &msg, 0);
    if (rc < 0) {
      free(nlh);
      syslog(LOG_NOTICE,"not recivemsg(): \n");
      return NULL;
    //  return 1;
    }

    recive  = (struct ReciveMsg*)malloc(sizeof (recive));
    memset(recive, 0, sizeof (recive));
    recive->length = rc;
    recive->msg = (char *)malloc(sizeof(char) * rc);
    strcpy(recive->msg, NLMSG_DATA(nlh));

    free(nlh);
    return recive;
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
      syslog(LOG_NOTICE, "not sending(): \n");
      return 1;
    }

    return 0;
}

char* readStatProc(char *procName){
    int *fd;
    int lenProc;
    char* filePath;
    struct stat fileStat;
    char* buff;
    int res;

    lenProc = strlen(procName);
    filePath = malloc(sizeof (char) * (lenProc + sizeof (PATH_CONFIG) + 2 + 5 ));
    memset(filePath, 0, (lenProc) + sizeof (PATH_CONFIG) + 3 + 5);
    strcat(filePath, PATH_CONFIG);
    strcat(filePath, "/");
    strcat(filePath, procName);
    strcat(filePath, "/stat");


    fd = open(filePath, O_RDWR);
    if(fd == NULL) {
        syslog (LOG_NOTICE, "file not opened(%d). %s\n", fd, filePath);
    }
    res = fstat(fd, &fileStat);
    buff = malloc(sizeof(char*) * fileStat.st_size + 1);
    memset(buff, 0, fileStat.st_size + 1);
    read(fd, buff, 10);
    close(fd);

    return buff;
}

void read_config(int sock_fd) {
    DIR *d;
    struct dirent *dir;
    char* state;
    char *sendMsg;

    d = opendir(PATH_CONFIG);
    if(d) {
        while ((dir = readdir(d)) != NULL) {
            if(strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
                continue;
            }
            state = readStatProc(dir->d_name);
            sendMsg = malloc(strlen(dir->d_name) + strlen(state) + 3);
            memset(sendMsg, 0, strlen(dir->d_name) + strlen(state) + 3);
            sendMsg[0] = NETLINK_OPCODE_RULE;
            strcat(sendMsg, dir->d_name);
            strcat(sendMsg, "&");
            strcat(sendMsg, state);

            syslog (LOG_NOTICE, "find dir: %s (%s)", dir->d_name, state);
            send_data(sock_fd, sendMsg);
        }
        closedir(d);
    }

//    send_data(sock_fd, DAEMON_HELLO);
}

void hook_new_rule(char* comm, char* ip, char* mode) {

    char *path;
    char *filePath;
    int commLen;
    FILE *fd;
    path = malloc(sizeof (char) * (strlen(comm) + strlen(PATH_CONFIG) + 2));
    filePath = malloc(sizeof (char) * (strlen(comm) + strlen(PATH_CONFIG) + 2 + 5));
    memset(path, 0, (strlen(comm) + strlen(PATH_CONFIG) + 2));
    memset(filePath, 0, (strlen(comm) + strlen(PATH_CONFIG) + 2 + 5));
    strcat(path, PATH_CONFIG);
    strcat(path, "/");
    strcat(path, comm);


    if(stat(path, &st) == -1) {
        mkdir(path, 0700);
    }

    strcat(filePath, path);
    strcat(filePath, "/");
    strcat(filePath, "stat");

    fd = fopen(filePath, "w+");
    if(fd == NULL) {
        syslog (LOG_NOTICE, "file not created. %s\n", filePath);
        return;
    }

    fprintf(fd, mode);

    fclose(fd);


}

int runProcess = 0;
void *openConfirmation(void *varg) {
    struct ArgPthread *argPthread = (struct ArgPthread *)varg;
    syslog (LOG_NOTICE, "theard created with (%s, %s).\n", argPthread->comm, argPthread->ip);
    FILE *fp;
    char command[500];
    char sendMsg[255];
    sprintf(command, "zenity --question \
            --title 'Новый процесс' \
            --text 'Новый процесс `%s` пытается получить доступ к IP `%s`'\
            --ok-label 'Разрешить'\
            --cancel-label 'Заблокировать'", argPthread->comm, argPthread->ip);
    fp = popen(command, "r");
    char ret;
    if(fp == NULL){
        syslog (LOG_NOTICE, "window not showind.\n");
        return;
    } else {
        ret = WEXITSTATUS(pclose(fp));
        syslog (LOG_NOTICE, "code: %i, %i, %i, %i, %i \n", EMFILE, ENFILE, EFAULT, ENOMEM, EAGAIN);
        syslog (LOG_NOTICE, "user click: %i. %i \n", ret, errno);
        if(ret == 0) {
            syslog (LOG_NOTICE, "user click: allow.\n", ret);
            hook_new_rule(argPthread->comm, argPthread->ip, COMMAND_ALLOW);
            sprintf(sendMsg, "%c%s&%s", NETLINK_OPCODE_RULE, argPthread->comm, COMMAND_ALLOW);
        } else {
            syslog (LOG_NOTICE, "user click: deny.\n", ret);
            hook_new_rule(argPthread->comm, argPthread->ip, COMMAND_DENY);
            sprintf(sendMsg, "%c%s&%s", NETLINK_OPCODE_RULE, argPthread->comm, COMMAND_DENY);
        }
        send_data(argPthread->socke_fd, sendMsg);
    }

    runProcess = 0;
}

int main()
{
    skeleton_daemon();

    struct ReciveMsg* data;
    unsigned nbytes;
    load_KE();

    int sock_fd;
    int rc;
    int exit;
    exit= 1;
    char* commName;
    int i;
    int ipv4;
    char ipv4s[16];
    struct in_addr ip_addr;
    struct ArgPthread argPthread;
    pthread_t tid;

    sock_fd = create_socket();

    send_data(sock_fd, DAEMON_HELLO);
    data = reciv_data(sock_fd);
    if(data == NULL || strcmp(data->msg, KERNEL_HELLO) != 0){
        syslog (LOG_NOTICE, "kernel not response hello. %p %s\n", data, data->msg);
        closelog();
        unload_KE();
        return -1;
    }

    if(stat(PATH_ROOT, &st) == -1) {
        mkdir(PATH_ROOT, 0700);
    }

    if(stat(PATH_CONFIG, &st) == -1) {
        mkdir(PATH_CONFIG, 0700);
    }

    read_config(sock_fd);

    syslog (LOG_NOTICE, "sfw daemon start.");
    for( ;exit; ) {
        data = reciv_data(sock_fd);
        if(data == NULL) {
            continue;
        }

        switch(data->msg[0]){
        case SEND_TYPE_EXIT:
            exit = 0;
            break;
        case SEND_TYPE_NEW_RULE:
            syslog (LOG_NOTICE, "kernel create new Rule: %s\n", data->msg);
            if(runProcess == 1) {
                syslog (LOG_NOTICE, "windows is showing already \n");
                break;
            }
            runProcess = 1;

            for(i=1;i<data->length;i++) {
                if(data->msg[i] == '&') {
                   commName = (char *)malloc(sizeof(char) * i);
                   memset(commName, 0, i);
                   strncat(commName, data->msg+1, i-1);
                   break;
                }
            }

            memcpy(&ipv4, data->msg+i+1, sizeof (int));
            ip_addr.s_addr = ipv4;
            syslog (LOG_NOTICE, "Process name: %s %d\n", commName, i);
            syslog (LOG_NOTICE, "ip: %s\n", inet_ntoa(ip_addr));
            argPthread.comm = commName;
            argPthread.ip = inet_ntoa(ip_addr);
            argPthread.socke_fd = sock_fd;

            pthread_create(&tid, NULL, openConfirmation, (void *)&argPthread);

            break;
        default:


            break;
        }

        syslog (LOG_NOTICE, "Cycle recive: %s\n", data->msg);
    }

    syslog (LOG_NOTICE, "First daemon terminated.");
    closelog();
    unload_KE();

    return EXIT_SUCCESS;
}
