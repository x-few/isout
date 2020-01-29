#ifndef _ISSHE_IPROXY_H_
#define _ISSHE_IPROXY_H_

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/listener.h"

#include "isout.h"
#include "iproxy_config.h"
#include "iproxy_event.h"
#include "iproxy_session.h"

#define IPROXY_DEFAULT_MEMPOOL_SIZE     4096

void iproxy_start(void *ctx);

#endif