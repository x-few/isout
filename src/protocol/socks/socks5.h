#ifndef _ISOUT_SOCKS5_H_
#define _ISOUT_SOCKS5_H_

#include "isshe_common.h"

#define SOCKS_PROTOCOL_V5               0x5

#define SOCKS5_METHOD_NO_AUTH_REQ        0x00
#define SOCKS5_METHOD_GSSAPI             0x01
#define SOCKS5_METHOD_USERNAME_PWD       0x02
#define SOCKS5_METHOD_NO_SUPPORT_METHOD  0xff

#define SOCKS5_CMD_CONNECT               0x01
#define SOCKS5_CMD_BIND                  0x02
#define SOCKS5_CMD_UDP_ASSOCIATE         0x03

#define SOCKS5_ADDR_TYPE_IPV4            0x01
#define SOCKS5_ADDR_TYPE_DOMAIN          0x03
#define SOCKS5_ADDR_TYPE_IPV6            0x04

#define SOCKS5_REPLY_SUCCEEDED           0x00
#define SOCKS5_REPLY_GENERAL_SVR_FAILURE 0x01
#define SOCKS5_REPLY_CONN_NOT_ALLOWED    0x02
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE    0x04
#define SOCKS5_REPLY_CONNECTION_REFUSED  0x05
#define SOCKS5_REPLY_TTL_EXPIRED         0x06
#define SOCKS5_REPLY_CMD_NOT_SUPPORTED   0x07
#define SOCKS5_REPLY_ATYPE_NOT_SUPPORTED 0x08
// 0x09-0xff: unassigned

typedef enum socks5_status_e                 socks5_status_t;
typedef struct socks5_selection_request_s    socks5_selection_request_t;
typedef struct socks5_selection_reply_s      socks5_selection_reply_t;
typedef struct socks5_request_s              socks5_request_t;
typedef struct socks5_reply_s                socks5_reply_t;


// socks5的连接状态
enum socks5_status_e {
    SOCKS5_STATUS_UNKNOWN = -1,
    SOCKS5_STATUS_WAITING_SELECTION = 0,
    SOCKS5_STATUS_WAITING_REQUEST = 1,
    SOCKS5_STATUS_CONNECTED = 2,
};

struct socks5_selection_request_s {
    isshe_uint8_t version;
    isshe_uint8_t nmethods;
    isshe_uint8_t methods;
};

struct socks5_selection_reply_s {
    isshe_uint8_t version;
    isshe_uint8_t method;
};

struct socks5_request_s {
    isshe_uint8_t version;
    isshe_uint8_t cmd;
    isshe_uint8_t rsv;
    isshe_uint8_t atype;
    isshe_uint8_t addr[0];
};

//#pragma pack(2)
struct socks5_reply_s {
    isshe_uint8_t version;
    isshe_uint8_t rep;
    isshe_uint8_t rsv;
    isshe_uint8_t atype;
    isshe_uint8_t addr[4];        // TODO 当前此应答只考虑IPv4，并且是本机(0.0.0.0)。
    isshe_uint16_t port;
};
//#pragma pack()


isshe_bool_t is_valid_socks5_selection_request(
    socks5_selection_request_t *request);

isshe_bool_t is_valid_socks5_request(socks5_request_t *request);

isshe_bool_t is_support_socks5_addr_type(isshe_uint8_t type);


#endif