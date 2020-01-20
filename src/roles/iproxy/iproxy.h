#ifndef _ISSHE_IPROXY_H_
#define _ISSHE_IPROXY_H_

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/listener.h"

#include "isout.h"

void iproxy_start(void *ctx);

#endif