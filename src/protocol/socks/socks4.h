#ifndef _ISOUT_SOCKS4_H_
#define _ISOUT_SOCKS4_H_

#include "isshe_common.h"

#define SOCKS_PROTOCOL_V4               0x4

#define SOCKS4_CMD_CONNECT               0x01
#define SOCKS4_CMD_BIND                  0x02

// reply cmd:
#define SOCKS4_REQUEST_GRANTED                          90
#define SOCKS4_REQUEST_REJECTED_OR_FAILED               91
#define SOCKS4_REQUEST_REJECTED_FOR_CONNECT_FAILED      92
#define SOCKS4_REQUEST_REJECTED_FOR_DIFF_USERID         93


typedef struct socks4_request_s              socks4_request_t;
typedef struct socks4_reply_s                socks4_reply_t;

// socks4的连接状态
enum socks4_status_e {
    SOCKS4_STATUS_WAITING_REQUEST = 1,
    SOCKS4_STATUS_CONNECTED = 2,
};

struct socks4_request_s
{
    isshe_uint8_t   version;
    isshe_uint8_t   cmd;
    isshe_uint16_t  dport;
    isshe_uint8_t   daddr[4];
    isshe_uint8_t   userid[1];      // 不支持userid，1字节为了存userid结束符NULL。
};

struct socks4_reply_s
{
    isshe_uint8_t   version;        // should be 0
    isshe_uint8_t   cmd;
    isshe_uint16_t  dport;
    isshe_uint8_t   daddr[4];
};

isshe_bool_t
is_valid_socks4_request(socks4_request_t *request);

#endif