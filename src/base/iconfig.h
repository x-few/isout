#ifndef _ISOUT_ICONFIG_H_
#define _ISOUT_ICONFIG_H_

#include "isout.h"
#include "iconfig.h"

typedef struct iconfig_s iconfig_t;

struct iconfig_s
{
    isshe_char_t    *config_file;
    isshe_json_t    *config_json;
    isshe_char_t    *log_file;
    isshe_int_t     log_level;
    isshe_log_t     *log;
    //ievent_t        *event;
};

void iconfig_print(iconfig_t *config);

void iconfig_parse(iconfig_t *conf, const char *file);

isshe_char_t *iconfig_log_parse(isshe_json_t *json, isshe_int_t *level);

isshe_int_t iconfig_connection_parse(isshe_json_t *json, iconnection_t *conn);

iconfig_t *iconfig_new();

void iconfig_free(iconfig_t **pconfig);

#endif