

#ifndef _ISOUT_ILOG_H_
#define _ISOUT_ILOG_H_

#include "isshe_common.h"

#define ilog_emerg      isshe_log_emerg
#define ilog_alert      isshe_log_alert
#define ilog_crit       isshe_log_cirt
#define ilog_error      isshe_log_error
#define ilog_warning    isshe_log_warning
#define ilog_notice     isshe_log_notice
#define ilog_info       isshe_log_info
#define ilog_debug      isshe_log_debug

#define ilog_emerg_errno    isshe_log_emerg_errno
#define ilog_alert_errno    isshe_log_alert_errno
#define ilog_crit_errno     isshe_log_crit_errno
#define ilog_error_errno    isshe_log_error_errno
#define ilog_warning_errno  isshe_log_warning_errno
#define ilog_notice_errno   isshe_log_notice_errno
#define ilog_info_errno     isshe_log_info_errno
#define ilog_debug_errno    isshe_log_debug_errno

typedef isshe_log_t ilog_t;
//#define ilog_t      isshe_log_t

ilog_t *ilog_init(isshe_uint_t level, isshe_char_t *filename);

ilog_t *ilog_get();

void ilog_uninit(ilog_t *log);

#endif