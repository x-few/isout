#ifndef _ISOUT_ICONNECTION_H_
#define _ISOUT_ICONNECTION_H_

#include "isout.h"

typedef struct iconnection_s iconnection_t;
typedef enum iconn_protocol_type_e iconn_protocol_type_t;
typedef enum iconn_addr_type_e iconn_addr_type_t;

enum iconn_protocol_type_e
{
    ICONN_PROTOCOL_UNKNOWN = -1,
    ICONN_PROTOCOL_SOCKS5 = 0,
    ICONN_PROTOCOL_ISOUT = 1,
};

enum iconn_addr_type_e
{
    ICONN_ADDR_TYPE_IPV4 = 0,
    ICONN_ADDR_TYPE_IPV6 = 1,
    ICONN_ADDR_TYPE_DOMAIN = 2,
};

struct iconnection_s
{
    isshe_uint16_t      port;
    //isshe_int_t         addr_type;
    isshe_sockaddr_t    addr;
    isshe_int_t         protocol;
    isshe_char_t        *addr_str;
    isshe_char_t        *protocol_str;
};


isshe_int_t iconn_protocol_type_get(const isshe_char_t *protocol_str);

isshe_int_t iconn_addr_type_get(const isshe_char_t *addr_str);

isshe_int_t iconn_addr_pton(const isshe_char_t *addr_str,
                            isshe_int_t type, void *res_addr);

#endif