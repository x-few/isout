#ifndef _ISOUT_IMASTER_SIGNAL_H_
#define _ISOUT_IMASTER_SIGNAL_H_

#include "isout.h"

void imaster_signal_handler(int signo);

isshe_int_t imaster_signal_init(ilog_t *log);

isshe_bool_t ismaster_signal_is_triggered(int signo);
void imaster_triggered_signal_add(int signo);
void imaster_triggered_signal_del(int signo);

isshe_int_t imaster_signal_mask(ilog_t *log, sigset_t *set);
isshe_int_t imaster_signal_unmask(ilog_t *log, sigset_t *set);

#endif