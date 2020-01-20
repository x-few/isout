

#include "isout.h"

// 和icon_protocol_t下标对应
static isshe_char_t*
iconn_protocols[] = {
    "socks5"
    "isout",
    NULL,
};


isshe_int_t
iconn_protocol_type_get(const isshe_char_t *protocol_str)
{
    isshe_int_t i;
    isshe_size_t len;

    len = strlen(protocol_str);
    for (i = 0; iconn_protocols[i]; i++)
    {
        if (strlen(iconn_protocols[i]) == len
        && isshe_memcmp(iconn_protocols[i], protocol_str, len) == 0) {
            return i;
        }
    }

    return ICONN_PROTOCOL_UNKNOWN;
}

isshe_int_t
iconn_addr_type_get(const isshe_char_t *addr_str)
{
    // TODO 根据addr字符串识别是什么地址
    return ICONN_ADDR_TYPE_IPV4;
}

isshe_int_t
iconn_addr_pton(const isshe_char_t *addr_str,
                isshe_int_t type, void *res_addr)
{
    isshe_int_t res;
    isshe_int_t af = AF_UNSPEC;

    switch (type)
    {
    case ICONN_ADDR_TYPE_IPV4:
        af = AF_INET;
        break;
    case ICONN_ADDR_TYPE_IPV6:
        af = AF_INET6;
        break;
    case ICONN_ADDR_TYPE_DOMAIN:
        // TODO 域名解析后存在到addr，然后直接return
        return ISSHE_SUCCESS;
    }

    if (af == AF_UNSPEC) {
        return ISSHE_FAILURE;
    }

    res = inet_pton(af, addr_str, (void *)res_addr);
    if (res != 1) {
        return ISSHE_FAILURE;
    }

    return ISSHE_SUCCESS;
}
