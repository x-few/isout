#ifndef _ISSHE_ISOUT_ENCODE_H_
#define _ISSHE_ISOUT_ENCODE_H_

#include "isshe_common.h"
#include "isout_protocol.h"

isshe_int_t isout_encode(
    isshe_int_t algo, isshe_char_t *key, isshe_char_t *iv,
    isshe_char_t *data, isshe_int_t data_len, isshe_log_t *log);

#endif