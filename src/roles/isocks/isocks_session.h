#ifndef _ISOUT_ISOCKS_SESSION_H_
#define _ISOUT_ISOCKS_SESSION_H_

#include "isocks.h"

#define ISOCKS_SESSION_FREE_IN          0x01        // 按位
#define ISOCKS_SESSION_FREE_OUT         0x02

typedef struct isocks_session_s isocks_session_t;

struct isocks_session_s
{
    isshe_connection_t      *inconn;
    isshe_connection_t      *outconn;
    ievent_buffer_event_t   *inbev;
    ievent_buffer_event_t   *outbev;
    isocks_config_t         *config;
    isshe_mempool_t         *mempool;
    isocks_socks5_info_t    socks5;        // 保存socks5的信息
};

void isocks_session_free(isocks_session_t *session, isshe_int_t flag);

#endif