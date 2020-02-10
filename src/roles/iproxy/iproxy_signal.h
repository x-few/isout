#ifndef _ISOUT_IPROXY_SIGNAL_H_
#define _ISOUT_IPROXY_SIGNAL_H_

#include "iproxy.h"

isshe_int_t iproxy_signal_init(isshe_log_t *log);

void iproxy_sighdr_backtrace(isshe_int_t signo);

#endif