
#ifndef _ISSHE_ISOUT_IEVENT_H_
#define _ISSHE_ISOUT_IEVENT_H_

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"

struct ievent_s
{
    struct event_base *evbase;
    struct evconnlistener *evlistener;
};

typedef struct ievent_s ievent_t;

#endif