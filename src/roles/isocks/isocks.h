#ifndef _ISOUT_ISOCKS_H_
#define _ISOUT_ISOCKS_H_

#include "isout.h"
#include "isout_protocol.h"
#include "isout_options.h"

#include "isocks_config.h"
#include "isocks_socks5.h"
#include "isocks_session.h"
#include "isocks_event.h"


#define ISOCKS_DEFAULT_MEMPOOL_SIZE        4096


void isocks_start(void *ctx);

#endif