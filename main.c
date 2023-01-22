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
#define FREE_RECIVE(data) free(data->msg);free(data);

void load_KE() {
    if(system("insmod /lib/module/$(shell uname -r)/extra/sfw_module.ko") == 0) {
        syslog(LOG_NOTICE, "daemon load module\n");
    } else {
        syslog(LOG_WARNING, "daemon not load module. Maby module is loaded already?\n");
    }
}

void unload_KE() {
    system("rmmod sfw_module");
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
    signal(SIGCHLD, SIG_DFL);
}

int create_socket() {
    int sock_fd;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TRANSFER_ID);
    if (sock_fd < 0) {
      syslog(LOG_CRIT, "socket don't create: \n");
      exit(-1);
    }

    return sock_fd;
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
      syslog(LOG_ERR,"data is not recived\n");
      return NULL;
    }

    recive  = (struct ReciveMsg*)malloc(sizeof (struct ReciveMsg));
    memset(recive, 0, sizeof (struct ReciveMsg));
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

    rc = sendmsg(sock_fd, &msg, 0);
    free(nlh);
    if (rc < 0) {
      syslog(LOG_ERR, "data is not sending: \n");
      return 1;
    }

    return 0;
}

char* readStatProc(char *procName){
    int fd;
    int lenProc;
    char* filePath;
    struct stat fileStat;
    char* buff;

    lenProc = strlen(procName);
    filePath = malloc(sizeof (char) * (lenProc + sizeof (PATH_CONFIG) + 3 + 5 ));
    memset(filePath, 0, (lenProc) + sizeof (PATH_CONFIG) + 3 + 5);
    strcat(filePath, PATH_CONFIG);
    strcat(filePath, "/");
    strcat(filePath, procName);
    strcat(filePath, "/stat");


    fd = open(filePath, O_RDWR);
    if(fd < 0) {
        syslog (LOG_ERR, "file not opened: %s\n", fd, filePath);
    }
    fstat(fd, &fileStat);
    buff = malloc(sizeof(char*) * fileStat.st_size + 1);
    memset(buff, 0, fileStat.st_size + 1);
    read(fd, buff, 10);
    close(fd);
    free(filePath);

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

            send_data(sock_fd, sendMsg);
            free(state);
            free(sendMsg);
        }
        closedir(d);
    }
}

void hook_new_rule(char* comm, char* ip, char* mode) {

    char *path;
    char *filePath;
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
    strcat(filePath, "/stat");
    free(path);

    fd = fopen(filePath, "w+");
    if(fd == NULL) {
        syslog (LOG_NOTICE, "file not created. %s\n", filePath);
        free(filePath);
        return;
    }

    fprintf(fd, mode);
    fclose(fd);
    free(filePath);

}

int runProcess = 0;
void *openConfirmation(void *varg) {
    struct ArgPthread *argPthread = (struct ArgPthread *)varg;
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
        syslog (LOG_ERR, "window not showind.\n");
        return NULL;
    } else {
        ret = WEXITSTATUS(pclose(fp));
        syslog (LOG_NOTICE, "press %i.\n", ret);
        switch (ret) {
        case 0:
            hook_new_rule(argPthread->comm, argPthread->ip, COMMAND_ALLOW);
            sprintf(sendMsg, "%c%s&%s", NETLINK_OPCODE_RULE, argPthread->comm, COMMAND_ALLOW);
            send_data(argPthread->socke_fd, sendMsg);
            break;
        case 1:
            hook_new_rule(argPthread->comm, argPthread->ip, COMMAND_DENY);
            sprintf(sendMsg, "%c%s&%s", NETLINK_OPCODE_RULE, argPthread->comm, COMMAND_DENY);
            send_data(argPthread->socke_fd, sendMsg);
            break;
        }
    }

    runProcess = 0;
    free(argPthread->comm);
    return NULL;
}

int main()
{
    skeleton_daemon();

    struct ReciveMsg* data;
    int sock_fd;
    int exit;
    exit= 1;
    int i;
    int ipv4;
    struct in_addr ip_addr;
    struct ArgPthread argPthread;
    pthread_t tid, tdefault;
    memset(&tid, 0, sizeof (pthread_t));
    memset(&tdefault, 0, sizeof (pthread_t));
    load_KE();
    syslog (LOG_NOTICE, "sfw daemon start.");

    sock_fd = create_socket();

    send_data(sock_fd, DAEMON_HELLO);
    data = reciv_data(sock_fd);
    if(data == NULL || strcmp(data->msg, KERNEL_HELLO) != 0){
        syslog (LOG_CRIT, "kernel not response hello. %p %s\n", data, data->msg);
        closelog();
        unload_KE();
        return -1;
    }
    FREE_RECIVE(data);

    if(stat(PATH_ROOT, &st) == -1) {
        mkdir(PATH_ROOT, 0700);
    }

    if(stat(PATH_CONFIG, &st) == -1) {
        mkdir(PATH_CONFIG, 0700);
    }

    read_config(sock_fd);

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
                   argPthread.comm = (char *)malloc(sizeof(char) * i);
                   memset(argPthread.comm, 0, i);
                   strncat(argPthread.comm, data->msg+1, i-1);
                   break;
                }
            }

            memcpy(&ipv4, data->msg+i+1, sizeof (int));
            ip_addr.s_addr = ipv4;
            argPthread.ip = inet_ntoa(ip_addr);
            argPthread.socke_fd = sock_fd;

            pthread_create(&tid, NULL, openConfirmation, (void *)&argPthread);
            break;
        }
        FREE_RECIVE(data);
    }
    if(pthread_equal(tid,tdefault) != 0) {
       pthread_join(tid, NULL);
    }

    syslog (LOG_NOTICE, "First daemon terminated.");
    closelog();
    unload_KE();

    return EXIT_SUCCESS;
}
