#include "isout.h"

void
isocks_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_socket_t fd, struct sockaddr *sockaddr,
    int socklen, void *data)
{
    // 打印对端的信息
    /*
    printf("\nfd: %d, addr:%s, port:%d\n", fd,
    inet_ntoa(((struct sockaddr_in*)sockaddr)->sin_addr),
    ntohs(((struct sockaddr_in*)sockaddr)->sin_port));
    */
    isshe_debug_print_addr(sockaddr);
}