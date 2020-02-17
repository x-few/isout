#include "socks5.h"

isshe_bool_t
is_valid_socks5_selection_request(socks5_selection_request_t *request)
{
    if (request->version != SOCKS_PROTOCOL_V5) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}

isshe_bool_t
is_valid_socks5_request(socks5_request_t *request)
{
    if (request->version != SOCKS_PROTOCOL_V5) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}

isshe_bool_t
is_support_socks5_addr_type(isshe_uint8_t type)
{
    switch (type)
    {
    case SOCKS5_ADDR_TYPE_DOMAIN:
    case SOCKS5_ADDR_TYPE_IPV4:
    case SOCKS5_ADDR_TYPE_IPV6:
        break;
    default:
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}