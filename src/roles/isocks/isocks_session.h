#ifndef _ISOUT_ISOCKS_SESSION_H_
#define _ISOUT_ISOCKS_SESSION_H_

#include "isout.h"

typedef struct isocks_session_s isocks_session_t;

struct isocks_session_s
{
    isshe_connection_t      *inconn;
    isshe_connection_t      *outconn;
    //ievent_t              *event;
    ievent_buffer_event_t   *inevb;
    ievent_buffer_event_t   *outevb;
    isocks_config_t         *config;
};

#endif