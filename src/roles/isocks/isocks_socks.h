#ifndef _ISOCKS_SOCKS_H_
#define _ISOCKS_SOCKS_H_

#include "isocks.h"

isshe_int_t isocks_socks5_selction_message_process(
    ievent_buffer_event_t *bev, isshe_log_t *log);

isshe_int_t isocks_socks5_request_process(
    ievent_buffer_event_t *bev, isshe_connection_t *conn,
    isshe_log_t *log, isshe_address_t *addr);

isshe_int_t
isocks_socks4_request_process(
    ievent_buffer_event_t *bev,
    isshe_connection_t *conn,
    isshe_log_t *log,
    isshe_address_t *info);

#endif