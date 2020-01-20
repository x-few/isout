#include "isout.h"

isshe_signal_t imaster_signals[] = {
    { ISSHE_SIGNAL_RECONFIGURE, "SIGHUP", "reload", imaster_signal_handler },
    { ISSHE_SIGNAL_REOPEN, "SIGUSR1", "reopen", imaster_signal_handler },
    { ISSHE_SIGNAL_SHUTDOWN, "SIGQUIT", "quit", imaster_signal_handler },
    { ISSHE_SIGNAL_TERMINATE, "SIGTERM", "stop", imaster_signal_handler },
    { ISSHE_SIGNAL_ALARM, "SIGALRM", "", imaster_signal_handler },
    { ISSHE_SIGNAL_INTERRUPT, "SIGINT", "", imaster_signal_handler },
    { ISSHE_SIGNAL_IO, "SIGIO", "", imaster_signal_handler },
    { ISSHE_SIGNAL_CHILD, "SIGCHLD", "", imaster_signal_handler },
    { ISSHE_SIGNAL_SYSTEM, "SIGSYS, SIG_IGN", "", SIG_IGN },
    { ISSHE_SIGNAL_PIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },
    { 0, NULL, "", NULL }
};

sigset_t imaster_triggered_signals;
sigset_t *pit_signals = &imaster_triggered_signals;

isshe_bool_t ismaster_signal_is_triggered(int signo)
{
    if (sigismember(pit_signals, signo)) {
        return ISSHE_TRUE;
    }
    return ISSHE_FALSE;
}

void imaster_triggered_signal_add(int signo)
{
    if (!ismaster_signal_is_triggered(signo)) {
        sigaddset(pit_signals, signo);
    }
}

void imaster_triggered_signal_del(int signo)
{
    if (ismaster_signal_is_triggered(signo)) {
        sigdelset(pit_signals, signo);
    }
}

void imaster_signal_handler(int signo)
{
    isshe_log_t *log = isshe_log_instance_get(ISSHE_LOG_NOTICE, NULL);
    isshe_log_debug(log, "%d handler signo %d", getpid(), signo);
    imaster_triggered_signal_add(signo);

    if (signo == SIGCHLD) {
        imaster_process_status_get();
    }
}

isshe_int_t imaster_signal_init(isshe_log_t *log)
{
    isshe_signal_t *sig;
    isshe_memzero(pit_signals, sizeof(sigset_t));

    for (sig = imaster_signals; sig->signo != 0; sig++) {
        if (isshe_sigaction(sig->signo, sig->handler) == ISSHE_SIGNAL_ERROR) {
            isshe_log_alert(log, "signaction(%d:%s) failed", 
                sig->signo, sig->signame);
            return ISSHE_FAILURE;
        }
    }

    return ISSHE_SUCCESS;
}

static isshe_int_t
do_imaster_signal_mask(isshe_log_t *log, sigset_t *set, isshe_int_t how)
{
    sigaddset(set, ISSHE_SIGNAL_CHILD);
    sigaddset(set, ISSHE_SIGNAL_ALARM);
    sigaddset(set, ISSHE_SIGNAL_IO);
    sigaddset(set, ISSHE_SIGNAL_INTERRUPT);
    sigaddset(set, ISSHE_SIGNAL_RECONFIGURE);
    sigaddset(set, ISSHE_SIGNAL_REOPEN);
    sigaddset(set, ISSHE_SIGNAL_TERMINATE);
    sigaddset(set, ISSHE_SIGNAL_SHUTDOWN);

    if (sigprocmask(how, set, NULL) == -1) {
        isshe_log_alert_errno(log, errno, "sigprocmask() failed");
    }
    return ISSHE_SUCCESS;
}

isshe_int_t imaster_signal_mask(isshe_log_t *log, sigset_t *set)
{
    return do_imaster_signal_mask(log, set, SIG_BLOCK);
}

isshe_int_t imaster_signal_unmask(isshe_log_t *log, sigset_t *set)
{
    return do_imaster_signal_mask(log, set, SIG_UNBLOCK);
}