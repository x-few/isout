#include "isout.h"


ievent_t *
ievent_create(isshe_mempool_t *mempool, isshe_log_t *log)
{
    ievent_t *event;

    event = isshe_mpalloc(mempool, sizeof(ievent_t));
    if (!event) {
        isshe_log_alert(log, "mpalloc event failed");
        return NULL;
    }

    event->base = event_base_new();
    if (!event->base) {
        isshe_log_alert(log, "new event base failed");
        return NULL;
    }

    event->nlistener = 0;
    event->listeners = NULL;
    event->mempool = mempool;
    event->log = log;

    return event;
}


void
ievent_destroy(ievent_t *event)
{
    ievent_listener_t *l;
    ievent_listener_t *tl;

    for (l = event->listeners; l; ) {
        tl = l->next;
        evconnlistener_free(l->listener);
        l->listener = NULL;
        isshe_mpfree(event->mempool, l, sizeof(ievent_listener_t));
        l = tl;
    }
    event->listeners = NULL;
    event->nlistener = 0;

    event_base_free(event->base);
    event->base = NULL;
    
    isshe_mpfree(event->mempool, event, sizeof(ievent_t));
}


ievent_listener_t *
ievent_listener_create(ievent_t *event,
    ievent_conn_listener_cb_t cb, void *data,
    isshe_sockaddr_t *addr, isshe_socklen_t socklen)
{
    ievent_listener_t *listener;

    listener = isshe_mpalloc(event->mempool, sizeof(ievent_listener_t));
    if (!listener) {
        return NULL;
    }

    listener->listener = evconnlistener_new_bind(event->base, cb, data,
        LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, 
        (struct sockaddr *)addr, socklen);

    if (!listener->listener) {
        isshe_mpfree(event->mempool, listener, sizeof(ievent_listener_t));
        isshe_log_alert(event->log, "cannot new listener for xxx(addr TODO!)");
        return NULL;
    }

    // add to list
    listener->next = event->listeners;
    event->listeners = listener;
    event->nlistener++;

    return listener;
}


void
ievent_listener_destroy(ievent_t *event, ievent_listener_t *listener)
{
    ievent_listener_t *l;
    ievent_listener_t *prel;

    // 是第一个
    if (event->listeners == listener) {
        l = event->listeners;
        event->listeners = listener->next;
    } else {
        // 非第一个
        prel = event->listeners;
        for (l = prel->next; l; l = l->next) {
            if (l == listener) {
                prel->next = l->next;
                break;
            }
            prel = l;
        }
    }

    if (l) {
        evconnlistener_free(l->listener);
        isshe_mpfree(event->mempool, l, sizeof(ievent_listener_t));
        event->nlistener--;
    } else {
        isshe_log_warning(event->log, "destroy listener not found");
    }
}

isshe_int_t
ievent_dispatch(ievent_t *event)
{
    return event_base_dispatch(event->base);
}

isshe_int_t
ievent_connection_close(isshe_socket_t fd)
{
    // TODO accept之后应该怎么关闭？bev要不要释放？！
    return evutil_closesocket(fd);
}


ievent_buffer_event_t *
ievent_buffer_event_socket_create(ievent_t *event, ievent_socket_t fd)
{
    ievent_buffer_event_t *bev;
    bev = bufferevent_socket_new(event->base, fd,
            BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    return bev;
}


void
ievent_buffer_event_socket_destroy(ievent_buffer_event_t * bev)
{
    // TODO
}

isshe_int_t
ievent_buffer_event_socket_connect(ievent_buffer_event_t *bev,
    isshe_sockaddr_t *sockaddr, isshe_socklen_t socklen)
{
    return bufferevent_socket_connect(bev,
        (struct sockaddr*)sockaddr, socklen);
}


void
ievent_buffer_event_setcb(ievent_buffer_event_t *bev,
    ievent_buffer_event_data_cb_t readcb,
    ievent_buffer_event_data_cb_t writecb,
    ievent_buffer_event_event_cb_t eventcb, void *cbarg)
{
    bufferevent_setcb(bev, readcb, writecb, eventcb, cbarg);
}


isshe_int_t
ievent_buffer_event_enable(ievent_buffer_event_t *bev, isshe_int_t event)
{
    return bufferevent_enable(bev, (short)event);
}

isshe_int_t
ievent_buffer_event_disable(ievent_buffer_event_t *bev, isshe_int_t event)
{
    return bufferevent_disable(bev, (short)event);
}

ievent_buffer_t *
ievent_buffer_event_get_input(ievent_buffer_event_t *bev)
{
	return bufferevent_get_input(bev);
}

ievent_buffer_t *
ievent_buffer_event_get_output(ievent_buffer_event_t *bev)
{
	return bufferevent_get_output(bev);
}

isshe_size_t
ievent_buffer_get_length(const ievent_buffer_t *buffer)
{
    return evbuffer_get_length(buffer);
}

isshe_size_t
ievent_buffer_event_read(ievent_buffer_event_t *bev, void *data, isshe_size_t size)
{
    return bufferevent_read(bev, data, size);
}

isshe_int_t
ievent_buffer_event_write(ievent_buffer_event_t *bev, const void *data, size_t size)
{
    return bufferevent_write(bev, data, size);
}

isshe_socket_t
ievent_buffer_event_getfd(ievent_buffer_event_t *bev)
{
    return bufferevent_getfd(bev);
}


void
ievent_buffer_event_free(ievent_buffer_event_t *bev)
{
    bufferevent_free(bev);
}

isshe_int_t
ievent_buffer_add_buffer(ievent_buffer_t *dst, ievent_buffer_t *src)
{
    return evbuffer_add_buffer(dst, src);
}

isshe_int_t
ievent_buffer_copyout(
    ievent_buffer_t *buf, void *data_out, size_t data_len)
{
    return evbuffer_copyout(buf, data_out, data_len);
}
