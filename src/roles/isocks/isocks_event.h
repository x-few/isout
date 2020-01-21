#ifndef _ISOUT_ISOCKS_EVENT_H_
#define _ISOUT_ISOCKS_EVENT_H_

#include "isout.h"

void isocks_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_socket_t fd, struct sockaddr *sockaddr,
    int socklen, void *data);

#endif