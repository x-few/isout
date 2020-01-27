#ifndef _ISOCKS_SOCKS5_H_
#define _ISOCKS_SOCKS5_H_

#include "isocks.h"

#define ISOCKS_DEFAULT_SOCKS_VERSION            0x5

#define ISOCKS_SOCKS5_METHOD_NO_AUTH_REQ        0x00
#define ISOCKS_SOCKS5_METHOD_GSSAPI             0x01
#define ISOCKS_SOCKS5_METHOD_USERNAME_PWD       0x02
#define ISOCKS_SOCKS5_METHOD_NO_SUPPORT_METHOD  0xff

#define ISOCKS_SOCKS5_CMD_CONNECT               0x01
#define ISOCKS_SOCKS5_CMD_BIND                  0x02
#define ISOCKS_SOCKS5_CMD_UDP_ASSOCIATE         0x03

#define ISOCKS_SOCKS5_ADDR_TYPE_IPV4            0x01
#define ISOCKS_SOCKS5_ADDR_TYPE_DOMAIN          0x03
#define ISOCKS_SOCKS5_ADDR_TYPE_IPV6            0x04

#define ISOCKS_SOCKS5_REPLY_SUCCEEDED           0x00
#define ISOCKS_SOCKS5_REPLY_GENERAL_SVR_FAILURE 0x01
#define ISOCKS_SOCKS5_REPLY_CONN_NOT_ALLOWED    0x02
#define ISOCKS_SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define ISOCKS_SOCKS5_REPLY_HOST_UNREACHABLE    0x04
#define ISOCKS_SOCKS5_REPLY_CONNECTION_REFUSED  0x05
#define ISOCKS_SOCKS5_REPLY_TTL_EXPIRED         0x06
#define ISOCKS_SOCKS5_REPLY_CMD_NOT_SUPPORTED   0x07
#define ISOCKS_SOCKS5_REPLY_ATYPE_NOT_SUPPORTED 0x08
// 0x09-0xff: unassigned


typedef enum isocks_socks5_status_e                 isocks_socks5_status_t;
typedef struct isocks_socks5_selection_request_s    isocks_socks5_selection_request_t;
typedef struct isocks_socks5_selection_reply_s      isocks_socks5_selection_reply_t;
typedef struct isocks_socks5_request_s              isocks_socks5_request_t;
typedef struct isocks_socks5_reply_s                isocks_socks5_reply_t;
typedef struct isocks_socks5_info_s                 isocks_socks5_info_t;

struct isocks_socks5_info_s
{
    isshe_sockaddr_t        *addr;
    isshe_char_t            *addr_text;
    isshe_int_t             addr_type;
    isshe_uint8_t           addr_len;
    isshe_uint16_t          port;
};

// socks5的连接状态
enum isocks_socks5_status_e {
    //SOCKS5_STATUS_UNKNOWN = -1,
    SOCKS5_STATUS_WAITING_SELECTION = 0,
    SOCKS5_STATUS_WAITING_REQUEST = 1,
    SOCKS5_STATUS_CONNECTED = 2,
};

struct isocks_socks5_selection_request_s {
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods;
};

struct isocks_socks5_selection_reply_s {
    uint8_t version;
    uint8_t method;
};

struct isocks_socks5_request_s {
    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atype;
    uint8_t addr[0];
};

//#pragma pack(2)
struct isocks_socks5_reply_s {
    uint8_t version;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atype;
    uint8_t addr[4];        // TODO 当前此应答只考虑IPv4，并且是本机(0.0.0.0)。
    uint16_t port;
};
//#pragma pack()

isshe_int_t socks5_selction_message_process(
    ievent_buffer_event_t *bev, isshe_log_t *log);

isshe_int_t socks5_request_process(
    ievent_buffer_event_t *bev, isshe_connection_t *conn,
    isshe_log_t *log, isocks_socks5_info_t *info);

#endif