#ifndef _ISOUT_IPROXY_EVENT_H_
#define _ISOUT_IPROXY_EVENT_H_

#include "iproxy.h"

void iproxy_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_socket_t fd, struct sockaddr *sockaddr,
    int socklen, void *data);

#endif