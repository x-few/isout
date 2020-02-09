
#include "iproxy.h"

void
iproxy_session_free(iproxy_session_t *session, isshe_int_t flag)
{
    isshe_log_t *log;

    log = session->config->log;
    if (IPROXY_SESSION_FREE_IN & flag) {
        isshe_log_debug(log, "session free: free in");
        if (session->inbev) {
            isshe_log_debug(log,
                "session free: free in bev: %p",session->inbev);
            ievent_buffer_event_free(session->inbev);
            session->inbev = NULL;
        }

        if (session->inconn) {
            isshe_connection_free(
                session->config->connpool, session->inconn);
            session->inconn = NULL;
        }

        if (session->inhdr) {
            isout_protocol_header_destroy(session->inhdr,session->mempool);
            session->inhdr = NULL;
        }

        if (session->inopts) {
            isout_protocol_options_destroy(
                session->inopts, session->mempool);
            session->inopts = NULL;
        }
    }

    if (IPROXY_SESSION_FREE_OUT & flag) {
        isshe_log_debug(log, "session free: free out");
        if (session->outbev) {
            isshe_log_debug(log, "session free: free out bev: %p", session->outbev);
            ievent_buffer_event_free(session->outbev);
            session->outbev = NULL;
        }

        if (session->outconn) {
            isshe_connection_free(
                session->config->connpool,
                session->outconn);
            session->outconn = NULL;
        }
    }

    // 如果两个都关闭了，就释放其余所有资源，如mempool
    if (!session->inconn && !session->outconn && session->mempool) {
        isshe_log_debug(log, "session free: free common");
        isshe_mempool_destroy(session->mempool);
    }
}
