#ifndef _ISSHE_ISOUT_ICONFIG_H_
#define _ISSHE_ISOUT_ICONFIG_H_

#include "ievent.h"

typedef struct iconfig_s iconfig_t;

struct iconfig_s
{
    ievent_t *event;
};

void iconfig_parse(iconfig_t *conf, const char *file);

#endif