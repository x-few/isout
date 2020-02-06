#ifndef _ISSHE_ISOUT_DECODE_H_
#define _ISSHE_ISOUT_DECODE_H_

#include "isshe_common.h"
#include "isout_protocol.h"

isshe_int_t isout_decode(isout_options_t *opts,
    isshe_char_t *data, isshe_size_t data_len, isshe_log_t *log);

#endif