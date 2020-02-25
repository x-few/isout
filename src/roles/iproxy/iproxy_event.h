#ifndef _ISOUT_IPROXY_EVENT_H_
#define _ISOUT_IPROXY_EVENT_H_

#include "iproxy.h"

void iproxy_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_fd_t fd, isshe_sa_t *sockaddr,
    int socklen, void *data);

#endif