#ifndef _ISOUT_ISOCKS_MODE_H_
#define _ISOUT_ISOCKS_MODE_H_

#include "isshe_common.h"

#if defined ISSHE_APPLE
static char *proxy_cmd_on = "";
static char *proxy_cmd_off = "";
#elif defined ISSHE_LINUX
static char *proxy_cmd_on = "";
static char *proxy_cmd_off = "";
#else
static char *proxy_cmd_on = "";
static char *proxy_cmd_off = "";
#endif

#endif