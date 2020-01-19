
#include "iproxy.h"


void iproxy_left_read_cb(struct bufferevent *bev, void *ctx)
{
    
}


void iproxy_right_read_cb(struct bufferevent *bev, void *ctx)
{

}


void iproxy_left_event_cb(
    struct bufferevent *bev, short what, void *ctx)
{

}

void iproxy_right_event_cb(
    struct bufferevent *bev, short what, void *ctx)
{

}

void iproxy_left_accept_cb(
    struct evconnlistener *listener,
    evutil_socket_t fd,
    struct sockaddr *sa,
    int socklen, void *ctx)
{
    // TODO xxx = ctx;
}

void iproxy_start(void *ctx)
{
    iconfig_t *config = (iconfig_t *)ctx;

    // TODO 屏蔽信号（需要吗）
    // TODO 设置进程标题
    isshe_process_title_set("isout: iproxy");
    sleep(30);

    // TODO...
    ilog_debug(config->log, "---in iproxy_start: pid = %d", getpid());
    
    // never return!
    exit(0);
}