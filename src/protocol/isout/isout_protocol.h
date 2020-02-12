/*
 * 定义/处理协议本身
 */

#ifndef _ISSHE_ISOUT_PROTOCOL_H_
#define _ISSHE_ISOUT_PROTOCOL_H_

// 标准
#include "isshe_common.h"
//#include "isout_options.h"

#define ISOUT_ALL_OPT_MAX_LEN       1024
#define ISOUT_HMAC_LEN              32

/*
+------------+------------+-------+
| 固定协议头部 | 可变协议选项 |  数据  |
+------------+------------+-------+
*/

typedef struct isout_protocol_header_s isout_protocol_header_t;
typedef struct isout_protocol_option_s isout_protocol_option_t;

struct isout_protocol_header_s
{
    isshe_uint16_t  opts_len;
    isshe_uint16_t  data_len;
};

struct isout_protocol_option_s{
    isshe_uint8_t type;
    isshe_uint8_t len;
    isshe_uint8_t data[0];
};

typedef enum
{
    ISOUT_STATUS_UNKNOWN = 0,
    ISOUT_STATUS_CONNECTED = 1,
    ISOUT_STATUS_READ_HDR = 2,
    ISOUT_STATUS_READ_OPTS = 3,
    ISOUT_STATUS_READ_DATA = 4,
}isout_protocol_status_e;

typedef enum
{
    ISOUT_CRYPTO_ALGO_UNKNOWN = 0,
    ISOUT_CRYPTO_ALGO_AES_128_CFB = 1,
} isout_crypto_algo_e;

typedef enum
{
    ISOUT_OPTION_RANDOM = 0,
    ISOUT_OPTION_IPV4,              // ipv4/domain/ipv6对应sock5的取值
    ISOUT_OPTION_PORT,
    ISOUT_OPTION_DOMAIN,
    ISOUT_OPTION_IPV6,
    ISOUT_OPTION_DATA_PROTOCOL,
    ISOUT_OPTION_ADDR,
    ISOUT_OPTION_DATA_LEN,
    ISOUT_OPTION_ADDR_TYPE,
    ISOUT_OPTION_CRYPTO_ALGO,
    ISOUT_OPTION_CRYPTO_KEY,
    ISOUT_OPTION_CRYPTO_IV,
    ISOUT_OPTION_SESSION_CRYPTO_ALGO,
    ISOUT_OPTION_SESSION_CRYPTO_KEY,
    ISOUT_OPTION_SESSION_CRYPTO_IV,
    ISOUT_OPTION_END = 255,
} isout_option_e;

void isout_protocol_header_set(
    isout_protocol_header_t *header,
    isshe_uint16_t data_len, isshe_uint16_t opts_len);

void isout_protocol_header_get(
    isout_protocol_header_t *dst, isout_protocol_header_t *src);

isshe_bool_t
isout_protocol_header_is_valid(isout_protocol_header_t *hdr);

void isout_protocol_header_print(
    isout_protocol_header_t *header, isshe_log_t *log);

isshe_size_t isout_option_append(isshe_char_t *buf,
    isshe_uint8_t type, isshe_uint8_t len, const void *data);

isshe_size_t isout_option_init_with_end(isshe_char_t *buf);

isshe_int_t isout_option_find_end(isshe_char_t *buf, isshe_size_t buflen);

isshe_int_t isout_option_insert(isshe_char_t *buf, isshe_size_t buflen,
    isshe_uint8_t type, isshe_uint8_t len, const void *data);

#endif