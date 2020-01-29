#ifndef _ISOUT_ISOCKS_CONFIG_H_
#define _ISOUT_ISOCKS_CONFIG_H_

#include "isocks.h"

#define ISOCKS_CONFIG_KEY               "isocks"
#define ISOCKS_CONNPOOL_DEFAULT_SIZE    512

typedef struct isocks_config_s isocks_config_t;

struct isocks_config_s
{
    isshe_connection_t  *inarray;
    isshe_connection_t  *outarray;
    isshe_int_t         nin;
    isshe_int_t         nout;
    isshe_log_t         *log;
    isshe_char_t        *log_file;
    isshe_int_t         log_level;
    isshe_size_t        connpool_size;
    isshe_connpool_t    *connpool;
    isshe_mempool_t     *mempool;
    ievent_t            *event;
};

isshe_int_t
isocks_config_parse(isocks_config_t *config, isshe_json_t *json, isshe_log_t *log);

void isocks_config_print(isocks_config_t *config, isshe_log_t *log);

#endif