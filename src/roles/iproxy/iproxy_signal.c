
#include "iproxy.h"

isshe_signal_t iproxy_signals[] = {
    { ISSHE_SIGNAL_SEGVIOLATION, "SIGSEGV", "SIGSEGV", iproxy_sighdr_backtrace },
    { ISSHE_SIGNAL_INTERRUPT, "SIGINT", "INTERRUPT", iproxy_sighdr_backtrace },
    { 0, NULL, "", NULL }
};
static isshe_log_t *ilog;

isshe_int_t iproxy_signal_init(isshe_log_t *log)
{
    isshe_signal_t *sig;

    for (sig = iproxy_signals; sig->signo != 0; sig++) {
        if (isshe_sigaction(sig->signo, sig->handler) == ISSHE_SIGNAL_ERROR) {
            isshe_log_alert(log, "signaction(%d:%s) failed", 
                sig->signo, sig->signame);
            return ISSHE_FAILURE;
        }
    }

    ilog = log;
    return ISSHE_SUCCESS;
}


void
iproxy_sighdr_backtrace(isshe_int_t signo)
{
    void *array[32];
    size_t size;
    char **strings;
    size_t i;

    size = backtrace(array, 32);
    strings = backtrace_symbols(array, size);

    isshe_log_info(ilog, "Obtained %zd stack frames.", size);

    for (i = 0; i < size; i++) {
        isshe_log_info(ilog, "%s", strings[i]);
    }

    isshe_free(strings, NULL);
    // TODO

    exit(0);
}