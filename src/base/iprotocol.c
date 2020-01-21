

#include "isout.h"

// 和icon_protocol_t下标对应
static isshe_char_t*
iprotocols[] = {
    "socks5"
    "isout",
    NULL,
};


isshe_int_t
iprotocol_type_get(const isshe_char_t *protocol_str)
{
    isshe_int_t i;
    isshe_size_t len;

    len = strlen(protocol_str);
    for (i = 0; iprotocols[i]; i++)
    {
        if (strlen(iprotocols[i]) == len
        && isshe_memcmp(iprotocols[i], protocol_str, len) == 0) {
            return i;
        }
    }

    return ICONN_PROTOCOL_UNKNOWN;
}