
#include "socks4.h"

isshe_bool_t
is_valid_socks4_request(socks4_request_t *request)
{
    if (request->version != SOCKS_PROTOCOL_V4) {
        return ISSHE_FALSE;
    }

    // TODO unsupport userid！
    if (request->userid[0] != 0) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}