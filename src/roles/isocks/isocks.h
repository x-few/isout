#ifndef _ISOUT_ISOCKS_H_
#define _ISOUT_ISOCKS_H_

#include "isout.h"

#include "isocks_config.h"
#include "isocks_socks5.h"
#include "isocks_session.h"
#include "isocks_event.h"


#define ISOCKS_DEFAULT_POOL_SIZE        4096


void isocks_start(void *ctx);

#endif