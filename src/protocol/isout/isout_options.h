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

#define ISOUT_PROTOCOL_OPTIONS_LEN_MAX      1024
#define ISOUT_PROTOCOL_DATA_LEN_MAX         4096

typedef struct isout_protocol_options_s isout_protocol_options_t;

struct isout_protocol_options_s
{
    //isshe_uint64_t      count;          // 计数器，初始化为0
    isshe_uint32_t      random;         // 随机数, 初始化为0
    //isshe_addr_info_t   *remote;
    /*
    isshe_char_t        *dname;         // domain name
    isshe_char_t        *ipv6;          // 初始化为NULL
    isshe_uint32_t      ipv4;           // 初始化为0
    */
    isshe_char_t        *addr;          // 地址
    isshe_uint8_t       addr_len;       // 地址长度
    isshe_uint16_t      port;           // 初始化为0
    isshe_uint8_t       addr_type;      // 初始化为0， ISSHE_SOCKS_ADDR_TYPE_DOMAIN
    /*
    isshe_uint8_t       dname_len;      // 初始化为0
    isshe_uint8_t       ipv6_len;       // 初始化为0
    */
    isshe_uint8_t       session_crypto_algo;
    isshe_char_t        *session_crypto_key;
    isshe_char_t        *session_crypto_iv;    
    isshe_uint32_t      data_len;       // 用户数据长度
};

isout_protocol_options_t *isout_protocol_options_create(
    isshe_mempool_t *mempool, isshe_log_t *log);

void isout_protocol_options_destroy(
    isout_protocol_options_t *opts,
    isshe_mempool_t *mempool);

isout_protocol_header_t *isout_protocol_header_create(
    isshe_mempool_t *mempool, isshe_log_t *log);

void isout_protocol_header_destroy(
    isout_protocol_header_t *opts,
    isshe_mempool_t *mempool);

isshe_int_t isout_protocol_options_from_string(
    isout_protocol_options_t *options, 
    isshe_char_t *stropts,
    isshe_int_t stropts_len,
    isshe_mempool_t *mempool,
    isshe_log_t *log);

isshe_int_t
isout_protocol_options_to_string(
    isout_protocol_options_t *opts,
    isshe_char_t *stropts,
    isshe_int_t *stropts_len,
    isshe_log_t *log);

isshe_int_t isout_protocol_options_string_len(
    isshe_char_t *buf, isshe_int_t buflen);

isshe_int_t isout_protocol_options_len(
    isout_protocol_options_t *opts);

isshe_bool_t isout_protocol_options_is_valid(
    isshe_char_t *buf, isshe_int_t buflen);

void isout_protocol_options_print(
    isout_protocol_options_t *opts, isshe_log_t *log);

isshe_int_t isout_protocol_send_opts_generate(
    isout_protocol_options_t *send, 
    isout_protocol_options_t *all,
    isshe_address_t *socks5,
    isshe_mempool_t *mempool,
    isshe_log_t *log);

void isout_protocol_send_opts_resume(
    isout_protocol_options_t *send, 
    isout_protocol_options_t *all,
    isshe_mempool_t *mempool,
    isshe_log_t *log);
#endif