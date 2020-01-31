#ifndef _ISOUT_OPTIONS_H_
#define _ISOUT_OPTIONS_H_

#include "isout_protocol.h"

#define ISOUT_OPTS_FLAG_DNAME       (1 << 0)
#define ISOUT_OPTS_FLAG_IPV4        (1 << 1)
#define ISOUT_OPTS_FLAG_IPV6        (1 << 2)
#define ISOUT_OPTS_FLAG_ADDR_TYPE   (1 << 3)
#define ISOUT_OPTS_FLAG_PORT        (1 << 4)

#define ISOUT_OPTION_DNAME_TO_STRING        (1 << 0)
#define ISOUT_OPTION_IPV4_TO_STRING         (1 << 1)
#define ISOUT_OPTION_IPV6_TO_STRING         (1 << 2)
#define ISOUT_OPTION_ADDR_TYPE_TO_STRING    (1 << 3)
#define ISOUT_OPTION_PORT_TO_STRING         (1 << 4)

#define ISOUT_OPTIONS_STRING_LEN_MAX        1024

typedef struct isout_options_s isout_options_t;

struct isout_options_s
{
    isshe_uint64_t      count;          // 计数器，初始化为0
    isshe_uint32_t      random;         // 随机数, 初始化为0
    isshe_char_t        *dname;         // domain name
    isshe_char_t        *ipv6;          // 初始化为NULL
    isshe_uint32_t      ipv4;           // 初始化为0
    isshe_uint16_t      port;           // 初始化为0
    isshe_uint8_t       addr_type;      // 初始化为0， ISSHE_SOCKS_ADDR_TYPE_DOMAIN
    isshe_uint8_t       dname_len;      // 初始化为0
    isshe_uint8_t       ipv6_len;       // 初始化为0
    isshe_uint32_t      data_len;  // 用户数据长度
};

isout_options_t *isout_options_create(isshe_mempool_t *mempool, isshe_log_t *log);
void isout_options_destroy(isout_options_t *opts, isshe_mempool_t *mempool);

isshe_int_t isout_options_from_string(
    isout_options_t *options, isshe_char_t *options_str,
    isshe_mempool_t *mempool, isshe_log_t *log);


isshe_char_t *isout_options_to_string(isout_options_t *opts,
    isshe_mempool_t *mempool, isshe_size_t *stropts_len);

isshe_size_t isout_options_string_len(isshe_char_t *buf, isshe_size_t buflen);
isshe_int_t isout_options_len(isout_options_t *opts);

isshe_bool_t isout_options_is_complete(isshe_char_t *buf, isshe_size_t buflen);

void isout_options_print(isout_options_t *opts, isshe_log_t *log);

#endif