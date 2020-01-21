
#ifndef _ISSHE_ISOUT_IEVENT_H_
#define _ISSHE_ISOUT_IEVENT_H_

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/listener.h"

#define ievent_conn_listener_cb_t   evconnlistener_cb
#define ievent_socket_t             evutil_socket_t

typedef struct event_base ievent_base_t;
typedef struct evconnlistener ievent_conn_listener_t;
typedef struct ievent_s ievent_t;
typedef struct ievent_listener_s ievent_listener_t;

typedef struct bufferevent ievent_buffer_t;

struct ievent_listener_s
{
    ievent_conn_listener_t  *listener;
    ievent_listener_t       *next;
};

struct ievent_s
{
    ievent_base_t           *base;
    ievent_listener_t       *listeners;
    isshe_int_t             nlistener;
    isshe_mempool_t         *mempool;
    isshe_log_t             *log;
};


ievent_t *ievent_create(isshe_mempool_t *mempool, isshe_log_t *log);
void ievent_destroy(ievent_t *event);

ievent_listener_t *ievent_listener_create(ievent_t *event,
    ievent_conn_listener_cb_t cb, void *data,
    isshe_sockaddr_t *addr, isshe_socklen_t socklen);

void ievent_listener_destroy(ievent_t *event, ievent_listener_t *listener);

isshe_int_t ievent_dispatch(ievent_t *event);

isshe_int_t ievent_connection_close(isshe_socket_t fd);

ievent_buffer_t *ievent_buffer_socket_create(
    ievent_t *event, ievent_socket_t fd);

void ievent_buffer_socket_destroy(ievent_buffer_t * evb);

#endif