#ifndef _ISOCKS_CONFIG_H_
#define _ISOCKS_CONFIG_H_

#include "isout.h"

#define ISOCKS_CONFIG_KEY       "isocks"

typedef struct isocks_config_s isocks_config_t;

struct isocks_config_s
{
    iconnection_t   in;
    iconnection_t   out;
    isshe_log_t     *log;
    isshe_char_t    *log_filename;
    isshe_int_t     log_level;
};

isshe_int_t
isocks_config_parse(isocks_config_t *config, isshe_json_t *json, isshe_log_t *log);

void isocks_config_print(isocks_config_t *config, isshe_log_t *log);

#endif