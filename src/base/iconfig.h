#ifndef _ISSHE_ISOUT_ICONFIG_H_
#define _ISSHE_ISOUT_ICONFIG_H_

#include "ievent.h"
#include "ilog.h"
#include "isshe_common.h"

typedef struct iconfig_s iconfig_t;

struct iconfig_s
{
    // TODO delete 20200106
    //isshe_int_t     argc;
    //isshe_char_t    **argv;
    isshe_char_t    *config_file;
    isshe_json_t    *config_json;
    isshe_char_t    *log_file;
    isshe_int_t     log_level;
    ilog_t          *log;
    ievent_t        *event;
};

void iconfig_print(iconfig_t *config);

void iconfig_parse(iconfig_t *conf, const char *file);

iconfig_t *iconfig_new();

void iconfig_free(iconfig_t **pconfig);

#endif