#ifndef _ISSHE_ISOUT_ISESSION_H_
#define _ISSHE_ISOUT_ISESSION_H_

#include "isout.h"

struct isession_s
{
    void *in;
    void *out;
    iconfig_t *config;
    //uint64_t flag;
    //ievent_t *ievent;
};

typedef struct isession_s isession_t;

#endif