#ifndef _ISOUT_IPROXY_SESSION_H_
#define _ISOUT_IPROXY_SESSION_H_

#include "iproxy.h"

#define IPROXY_SESSION_FREE_IN          0x01        // 按位
#define IPROXY_SESSION_FREE_OUT         0x02

typedef struct iproxy_session_s iproxy_session_t;

struct iproxy_session_s
{
    isshe_connection_t      *inconn;
    isshe_connection_t      *outconn;
    ievent_buffer_event_t   *inbev;
    ievent_buffer_event_t   *outbev;
    iproxy_config_t         *config;
    isout_options_t         *inopts;
    isshe_char_t            *inbuf;
    isshe_size_t            inbuf_len;
    isshe_size_t            inbuf_used_len;
    isshe_size_t            stropts_len;
    isshe_mempool_t         *mempool;
    isshe_uchar_t           in_read_opts:1;
    //isshe_uchar_t           in_read_data:1;
};

void iproxy_session_free(iproxy_session_t *session, isshe_int_t flag);

#endif