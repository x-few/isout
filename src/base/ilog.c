
#include "isout.h"

ilog_t *ilog_init(isshe_uint_t level, isshe_char_t *filename)
{
    return isshe_log_instance_get(level, filename);
}

ilog_t *ilog_get()
{
    return isshe_log_instance_get(ISSHE_LOG_NOTICE, NULL);
}

void ilog_uninit(ilog_t *log)
{
    isshe_log_free(log);
}