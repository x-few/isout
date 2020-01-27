#include "isocks.h"


isshe_int_t
isocks_event_transfer_data(ievent_buffer_event_t *srcbev,
    ievent_buffer_event_t *dstbev, isshe_log_t *log)
{
    ievent_buffer_t *src, *dst;

    src = ievent_buffer_event_get_input(srcbev);
    dst = ievent_buffer_event_get_output(dstbev);

    isshe_log_debug(log, "transfer: %p(%u) -> %p(%lu)",
        srcbev, ievent_buffer_get_length(src),
        dstbev, ievent_buffer_get_length(dst));

    evbuffer_add_buffer(dst, src);

    return ISSHE_SUCCESS;
}

void isocks_event_in_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    isocks_session_t    *session = (isocks_session_t *)ctx;
    isshe_connection_t  *inconn;
    isshe_log_t         *log;

    log = session->config->log;

    inconn = session->inconn;
    switch (inconn->status)
    {
    case SOCKS5_STATUS_CONNECTED:
        // TODO 加密、转发到out
        //sisshe_log_debug(log, "sock5 connected!!!");
        isocks_event_transfer_data(session->inbev, session->outbev, log);
        break;
    case SOCKS5_STATUS_WAITING_SELECTION:
        if (socks5_selction_message_process(bev, log) == ISSHE_FAILURE) {
            // TODO free fd
            return;
        }
        inconn->status = SOCKS5_STATUS_WAITING_REQUEST;
        break;
    case SOCKS5_STATUS_WAITING_REQUEST:
        if (socks5_request_process(bev, session->inconn,
        log, &session->socks5) == ISSHE_FAILURE) {
            // TODO free fd
            return;
        }
        inconn->status = SOCKS5_STATUS_CONNECTED;
        break;
    default:
        break;
    }
}


void isocks_event_out_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    isocks_session_t *session = (isocks_session_t *)ctx;
    isshe_log_t         *log;

    log = session->config->log;

    // 读取、解密

    // 转发到in
    isocks_event_transfer_data(session->outbev, session->inbev, log);
}


void isocks_event_in_event_cb(
    ievent_buffer_event_t *bev, short what, void *ctx)
{
    isocks_session_t        *session = (isocks_session_t *)ctx;
    isshe_log_t             *log;
    ievent_buffer_event_t   *partner;
    isshe_size_t            len;

    log = session->config->log;
    partner = session->outbev;

    assert(bev == session->inbev);

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno) {
                isshe_log_alert_errno(log, errno, "in connection error");
            }
        }

        if (partner) {
            // 把所有数据读出来，发给partner
            isocks_event_in_read_cb(bev, ctx);
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, EV_READ);
            } else {
                // free partner
                isocks_session_free(session, ISOCKS_SESSION_FREE_OUT);
            }
        }

        isocks_session_free(session, ISOCKS_SESSION_FREE_IN);
    }
}

void isocks_event_out_event_cb(
    ievent_buffer_event_t *bev, short what, void *ctx)
{
    isocks_session_t        *session = (isocks_session_t *)ctx;
    isshe_log_t             *log;
    ievent_buffer_event_t   *partner;
    isshe_size_t            len;

    log = session->config->log;
    partner = session->inbev;

    assert(bev == session->outbev);

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno) {
                isshe_log_alert_errno(log, errno, "out connection error");
            }
        }

        if (partner) {
            // 把所有数据读出来，发给partner
            isocks_event_out_read_cb(bev, ctx);
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, EV_READ);
            } else {
                // free partner
                isocks_session_free(session, ISOCKS_SESSION_FREE_IN);
            }
        }

        isocks_session_free(session, ISOCKS_SESSION_FREE_OUT);
    }
}


// TODO 考虑优化连接下一跳。
// 方案1：现在的实现，每个连接都用新的。
// 方案2：建立固定数量的隧道，每个连接都共用这些隧道。
static isshe_int_t
isocks_event_connect_to_next(ievent_buffer_event_t *evb,
    isshe_connection_t *conn, isshe_sockaddr_t *sockaddr,
    isshe_socklen_t socklen, isshe_log_t *log)
{
    if (ievent_buffer_event_socket_connect(evb, sockaddr, socklen) < 0) {
        isshe_log_alert_errno(log, errno, "connect to xxx failed");
        return ISSHE_FAILURE;
    }

    conn->sockaddr = sockaddr;
    conn->socklen = socklen;
    // conn->fd = fd            // TODO 需要再补充，从evb中获取

    return ISSHE_TRUE;
}


// TODO !!!
// 注意不要修改了array的内容
static isshe_connection_t *
isocks_event_select_next(isshe_connection_t *array, isshe_int_t array_len)
{
    return &array[0];
}


void
isocks_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_socket_t fd, struct sockaddr *sockaddr,
    int socklen, void *data)
{
    isocks_config_t     *config;
    isshe_mempool_t     *mempool = NULL;
    isocks_session_t    *session = NULL;
    isshe_connection_t  *out_conn = NULL;

    config = (isocks_config_t *)data;
    isshe_debug_print_addr(sockaddr, config->log);  // DEBUG

    // TODO 实现完再进行内存使用统计，再优化这里的内存池大小。
    // 新建一个内存池(默认一页），供此连接使用
    mempool = isshe_mempool_create(getpagesize(), config->log);
    if (!mempool) {
        isshe_log_alert(config->log, "create memory pool for connection failed");
        goto isocks_event_accept_error;
    }

    // 分配一个session
    session = isshe_mpalloc(mempool, sizeof(isocks_session_t));
    if (!session) {
        isshe_log_alert(config->log, "malloc session failed");
        goto isocks_event_accept_error;
    }

    // 从内存池中取两个连接
    session->inconn = isshe_connection_get(config->connpool);
    if (!session->inconn) {
        isshe_log_alert(config->log, "get inbound connection failed");
        goto isocks_event_accept_error;
    }
    
    session->outconn = isshe_connection_get(config->connpool);
    if (!session->outconn) {
        isshe_log_alert(config->log, "get outbound connection failed");
        goto isocks_event_accept_error;
    }

    // new bufferevent
    session->inbev = ievent_buffer_event_socket_create(config->event, fd);
    session->outbev = ievent_buffer_event_socket_create(config->event, ISSHE_INVALID_FILE);

    // 选择下一跳信息
    out_conn = isocks_event_select_next(config->outarray, config->nout);
    if (!out_conn) {
        isshe_log_alert(config->log, "select next failed");
        goto isocks_event_accept_error;
    }

    // 连接下一跳（出口）。NOTE：共用了sockaddr。
    if (isocks_event_connect_to_next(session->outbev,
    session->outconn, out_conn->sockaddr,
    out_conn->socklen, config->log) == ISSHE_FAILURE) {
        isshe_log_alert(config->log, "connect to next failed");
        goto isocks_event_accept_error;
    }

    // 设置入口回调，读取数据
    // 设置出口回调
    session->mempool = mempool;
    session->config = config;
    session->inconn->fd = fd;
    session->inconn->data = (void *)session;
    session->inconn->status = SOCKS5_STATUS_WAITING_SELECTION;
    session->inconn->mempool = mempool;
    session->outconn->fd = ievent_buffer_event_getfd(session->outbev);
    session->outconn->mempool = mempool;
    session->outconn->data = (void *)session;

    ievent_buffer_event_setcb(session->inbev, isocks_event_in_read_cb, 
        NULL, isocks_event_in_event_cb, (void*)session); //->outconn);
    ievent_buffer_event_enable(session->inbev, EV_READ|EV_WRITE);
    ievent_buffer_event_setcb(session->outbev, isocks_event_out_read_cb, 
        NULL, isocks_event_out_event_cb, (void*)session); //->inconn);
    ievent_buffer_event_enable(session->outbev, EV_READ|EV_WRITE);

    return;

isocks_event_accept_error:
    if (session) {
        if (session->inconn) {
            isshe_connection_free(config->connpool, session->inconn);
        }

        if (session->outconn) {
            isshe_connection_free(config->connpool, session->outconn);
        }
        
        isshe_mpfree(mempool, session, sizeof(isocks_session_t));
    }

    if (mempool) {
        isshe_mempool_destroy(mempool);
    }

    // TODO 怎么直接关闭连接？
    ievent_connection_close(fd);
}