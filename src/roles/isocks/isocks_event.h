#ifndef _ISOUT_ISOCKS_EVENT_H_
#define _ISOUT_ISOCKS_EVENT_H_

#include "isocks.h"

void isocks_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_fd_t fd, isshe_sa_t *sockaddr,
    int socklen, void *data);

#endif