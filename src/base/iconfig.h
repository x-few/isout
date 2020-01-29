#ifndef _ISOUT_ICONFIG_H_
#define _ISOUT_ICONFIG_H_

#include "isout.h"

typedef struct iconfig_s iconfig_t;

struct iconfig_s
{
    isshe_char_t        *config_file;
    isshe_json_t        *config_json;
    isshe_char_t        *log_file;
    isshe_int_t         log_level;
    isshe_log_t         *log;
    isshe_connection_t  *inarray;
    isshe_connection_t  *outarray;
    isshe_int_t         nin;
    isshe_int_t         nout;
    isshe_size_t        connpool_size;
    isshe_connpool_t    *connpool;
    isshe_mempool_t     *mempool;
};

void iconfig_print(iconfig_t *config);

void iconfig_parse(iconfig_t *conf, const char *file);

isshe_char_t *iconfig_log_parse(isshe_json_t *json, isshe_int_t *level);

isshe_connection_t *iconfig_connection_parse(isshe_mempool_t *pool,
    isshe_json_t *json_array, isshe_int_t *res_nconn);

iconfig_t *iconfig_create();

void iconfig_destroy(iconfig_t **pconfig);

#endif