/*
 * 定义/处理协议本身
 */

#ifndef _ISSHE_ISOUT_PROTOCOL_H_
#define _ISSHE_ISOUT_PROTOCOL_H_

// 标准
#include "isshe_common.h"
#include "isshe_options.h"

#define ISOUT_ALL_OPT_MAX_LEN       1024
#define ISOUT_HMAC_LEN              32

/*
+------------+----------+----------+
| 消息验证码 | 协议选项 | 加密数据 |
+------------+----------+----------+
*/

typedef struct isout_option_s isout_option_t;
typedef enum isout_opt_e isout_option_e;

struct isout_option_s{
    isshe_uint8_t type;
    isshe_uint8_t len;
    isshe_uint8_t data[0];
};

enum isout_opt_e {
    ISOUT_OPTION_COUNT,
    ISOUT_OPTION_RANDOM,
    ISOUT_OPTION_DATA_PROTOCOL,
    ISOUT_OPTION_DATA_LEN,
    ISOUT_OPTION_IPV4,
    ISOUT_OPTION_IPV6,
    ISOUT_OPTION_DOMAIN,
    ISOUT_OPTION_PORT,
    ISOUT_OPTION_ADDR_TYPE,
    ISOUT_OPTION_CRYPTO_ALGO,
    ISOUT_OPTION_CRYPTO_KEY,
    ISOUT_OPTION_CRYPTO_IV,
    ISOUT_OPTION_END = 255,
};

isshe_int_t isout_option_append(isshe_char_t *buf,
    isshe_uint8_t type, isshe_uint8_t len, const void *data);

void isout_option_init_with_end(isshe_char_t *buf);

isshe_int_t isout_options_len(isshe_char_t *buf);

isshe_int_t isout_option_find_end(isshe_char_t *buf);

isshe_int_t isout_option_insert(isshe_char_t *buf,
    isshe_uint8_t type, isshe_uint8_t len, const void *data);

#endif