
#include "isocks.h"

void
isocks_session_free(isocks_session_t *session, isshe_int_t flag)
{
    isshe_log_t *log;

    log = session->config->log;
    if (ISOCKS_SESSION_FREE_IN & flag) {
        isshe_log_debug(log, "session free: free in");
        if (session->inbev) {
            isshe_log_debug(log, "session free: free in bev: %p", session->inbev);
            ievent_buffer_event_free(session->inbev);
            session->inbev = NULL;
        }

        if (session->inconn) {
            isshe_connection_free(session->config->connpool, session->inconn);
            session->inconn = NULL;
        }
    }

    if (ISOCKS_SESSION_FREE_OUT & flag) {
        isshe_log_debug(log, "session free: free out");
        if (session->outbev) {
            isshe_log_debug(log, "session free: free out bev: %p", session->outbev);
            ievent_buffer_event_free(session->outbev);
            session->outbev = NULL;
        }

        if (session->outconn) {
            isshe_connection_free(session->config->connpool, session->outconn);
            session->outconn = NULL;
        }

        if (session->outhdr) {
            isout_protocol_header_destroy(session->outhdr,session->mempool);
            session->outhdr = NULL;
        }

        if (session->outopts) {
            isout_protocol_options_destroy(session->outopts, session->mempool);
            session->outopts = NULL;
        }
    }

    // 如果两个都关闭了，就释放其余所有资源，如mempool
    if (!session->inconn && !session->outconn && session->mempool) {
        if (session->inbytes > 1024 * 1024 || session->outbytes > 1024 * 1024) {
            isshe_log_debug(log, "inbytes = %ud, outbytes = %ud", session->inbytes, session->outbytes);
            exit(0);
        }
        isshe_log_debug(log, "session free: free common");
        isshe_mempool_destroy(session->mempool);
    }
}
