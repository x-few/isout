#ifndef _ISOUT_IPROXY_CONFIG_H_
#define _ISOUT_IPROXY_CONFIG_H_

#include "iproxy.h"

#define IPROXY_CONFIG_KEY               "iproxy"
#define IPROXY_CONNPOOL_DEFAULT_SIZE    512

typedef struct iproxy_config_s iproxy_config_t;

struct iproxy_config_s
{
    isshe_connection_t  *inarray;
    isshe_int_t         nin;
    isshe_log_t         *log;
    isshe_char_t        *log_file;
    isshe_int_t         log_level;
    isshe_size_t        connpool_size;
    isshe_connpool_t    *connpool;
    isshe_mempool_t     *mempool;
    ievent_t            *event;
};

isshe_int_t
iproxy_config_parse(iproxy_config_t *config, isshe_json_t *json, isshe_log_t *log);

void iproxy_config_print(iproxy_config_t *config, isshe_log_t *log);

#endif