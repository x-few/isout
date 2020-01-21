#ifndef _ISOUT_IPROTOCOL_H_
#define _ISOUT_IPROTOCOL_H_

#include "isout.h"


typedef enum iprotocol_type_e iprotocol_type_t;


enum iprotocol_type_e
{
    ICONN_PROTOCOL_UNKNOWN = -1,
    ICONN_PROTOCOL_SOCKS5 = 0,
    ICONN_PROTOCOL_ISOUT = 1,
};

isshe_int_t iprotocol_type_get(const isshe_char_t *protocol_str);


#endif