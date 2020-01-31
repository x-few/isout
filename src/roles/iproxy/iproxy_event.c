#include "iproxy.h"

static isshe_int_t
iproxy_event_connect_to_next(
    ievent_buffer_event_t *bev,
    isshe_sockaddr_t *sockaddr,
    isshe_socklen_t socklen, isshe_log_t *log)
{
    if (ievent_buffer_event_socket_connect(bev, sockaddr, socklen) < 0) {
        isshe_log_alert_errno(log, errno, "connect to xxx failed");
        return ISSHE_FAILURE;
    }

    return ISSHE_SUCCESS;
}

isshe_int_t
iproxy_event_transfer_data2(ievent_buffer_event_t *dstbev,
    ievent_buffer_event_t *srcbev, isshe_size_t data_len, isshe_log_t *log)
{
    isshe_char_t        buf[ISSHE_DEFAULT_BUFFER_LEN] = {0};
    isshe_size_t        buf_len = ISSHE_DEFAULT_BUFFER_LEN;
    isshe_size_t        read_len = 0;

    isshe_log_debug(log, "iproxy transfer: %p -> %p: %u",
        srcbev, dstbev, data_len);

    while(data_len > 0) {
        read_len = data_len < buf_len ? data_len : buf_len;
        ievent_buffer_event_read(srcbev, buf, read_len);
        ievent_buffer_event_write(dstbev, buf, read_len);
        data_len -= read_len;
    }

    return ISSHE_SUCCESS;
}

isshe_int_t
iproxy_event_transfer_data(ievent_buffer_event_t *dstbev,
    ievent_buffer_event_t *srcbev, isshe_log_t *log)
{
    ievent_buffer_t *src, *dst;

    src = ievent_buffer_event_get_input(srcbev);
    dst = ievent_buffer_event_get_output(dstbev);

    isshe_log_debug(log, "iproxy transfer: %p(%u) -> %p(%lu)",
        srcbev, ievent_buffer_get_length(src),
        dstbev, ievent_buffer_get_length(dst));

    ievent_buffer_add_buffer(dst, src);

    return ISSHE_SUCCESS;
}


// TODO 重构这里
void iproxy_event_in_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    iproxy_session_t    *session = (iproxy_session_t *)ctx;
    isshe_log_t         *log;
    isshe_size_t        len;
    isshe_size_t        remain_len;
    isshe_size_t        stropts_len;
    isshe_connection_t  *outconn;

    log = session->config->log;

    // 选项数据更新到连接中
    if (session->inconn->status != ISOUT_STATUS_CONNECTED) {
        // 读
        remain_len = session->inbuf_len - session->inbuf_used_len;
        if (remain_len <= 0) {
            isshe_log_warning(log, "isout options buffer remain lenght = 0");
            // TODO 禁用读写、关闭、释放连接
            return ;
        }
        len = ievent_buffer_get_length(ievent_buffer_event_get_input(session->inbev));
        len = len < remain_len ? len : remain_len;
        len = ievent_buffer_event_read(session->inbev,
            session->inbuf + session->inbuf_used_len, len);
        session->inbuf_used_len += len;

        // 解密

        
        // 检查是否是完整的选项
        stropts_len = isout_options_string_len(
            session->inbuf, session->inbuf_used_len);
        if (stropts_len == ISSHE_FAILURE) {
            // 继续等待更多数据
            isshe_log_debug(log, "iproxy in: waiting more data");
            return;
        }

        // 解析选项
        if (isout_options_from_string(
            session->inopts, session->inbuf,
            session->mempool, log) == ISSHE_FAILURE) {
            
            isshe_log_warning(log, "isout options parse failed");
            // TODO 禁用读写、关闭、释放连接
            return ;
        }

        isout_options_print(session->inopts, log);

        outconn = session->outconn;
        outconn->addr_text = isshe_mpalloc(session->mempool, session->inopts->dname_len + 1);
        if (!outconn->addr_text) {
            isshe_log_alert(log, "mpalloc addr_text failed");
            // TODO 禁用读写、关闭、释放连接
            return ;
        }
        isshe_memcpy(outconn->addr_text, session->inopts->dname, session->inopts->dname_len);
        outconn->addr_text[session->inopts->dname_len] = '\0';

        outconn->sockaddr = isshe_mpalloc(session->mempool, sizeof(isshe_sockaddr_t));
        if (!outconn->sockaddr) {
            isshe_log_alert(log, "mpalloc sockaddr failed");
            // TODO 禁用读写、关闭、释放连接
            return ;
        }

        isshe_log_debug(log, "outconn->addr_text = (%d)%s",
            strlen(outconn->addr_text), outconn->addr_text);

        // TODO 解析成sockaddr
        if (isshe_conn_addr_pton(outconn->addr_text,
        ISSHE_CONN_ADDR_TYPE_DOMAIN, outconn->sockaddr,
        &outconn->socklen) == ISSHE_FAILURE) {
            isshe_log_alert(log, "convert addr string to socksaddr failed");
            return ;
        }

        isshe_log_debug(log, "set sock port = %d", session->inopts->port);
        isshe_conn_port_set(outconn->sockaddr, session->inopts->port);

        isshe_debug_print_addr((struct sockaddr *)outconn->sockaddr, log);

        // 连接下一跳（需要的话）
        if (iproxy_event_connect_to_next(
            session->outbev, outconn->sockaddr,
            outconn->socklen, log) == ISSHE_FAILURE) {
            
            // TODO 禁用读写、关闭、释放连接
            isshe_log_alert(log, "connect to xx(TODO) failed");
            return;
        }

        session->inconn->status = ISOUT_STATUS_CONNECTED;

        // 转发数据
        if (session->inbuf_used_len - stropts_len > 0) {
            isshe_log_debug(log, "ievent_buff_event_write %d bytes",
                session->inbuf_used_len - stropts_len);
            ievent_buffer_event_write(session->outbev,
                session->inbuf + stropts_len,
                session->inbuf_used_len - stropts_len);
        }
    } else {
        // TODO 解密
    }

    // 转发数据
    iproxy_event_transfer_data(session->outbev,
        session->inbev, session->config->log);
    //iproxy_event_transfer_data2(session->outbev,
    //    session->inbev, session->inopts->data_len, log);
}


void iproxy_event_out_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    iproxy_session_t *session = (iproxy_session_t *)ctx;
    isshe_log_t         *log;
    isshe_char_t        stropts[128] = {0};
    isshe_size_t        stropts_len = 0;
    isshe_size_t        data_len = 0;

    log = session->config->log;

    // 读

    // 加密

    /*
    // 加选项
    data_len = ievent_buffer_get_length(
        ievent_buffer_event_get_input(session->outbev));
    stropts_len += isout_option_append(stropts + stropts_len,
        ISOUT_OPTION_DATA_LEN, sizeof(isshe_uint32_t), &data_len);
    stropts_len += isout_option_append(
        stropts + stropts_len,ISOUT_OPTION_END, 0, NULL);

    // 转发选项
    ievent_buffer_event_write(session->inbev, stropts, stropts_len);

    // 转发数据
    iproxy_event_transfer_data2(session->inbev, session->outbev, data_len, log);
    */

    iproxy_event_transfer_data(session->inbev, session->outbev, log);
}


void iproxy_event_in_event_cb(
    ievent_buffer_event_t *bev, short what, void *ctx)
{
    iproxy_session_t        *session = (iproxy_session_t *)ctx;
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
            iproxy_event_in_read_cb(bev, ctx);
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, EV_READ);
            } else {
                // free partner
                iproxy_session_free(session, IPROXY_SESSION_FREE_OUT);
            }
        }

        iproxy_session_free(session, IPROXY_SESSION_FREE_IN);
    }
}

void iproxy_event_out_event_cb(
    ievent_buffer_event_t *bev, short what, void *ctx)
{
    iproxy_session_t        *session = (iproxy_session_t *)ctx;
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
            iproxy_event_out_read_cb(bev, ctx);
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, EV_READ);
            } else {
                // free partner
                iproxy_session_free(session, IPROXY_SESSION_FREE_IN);
            }
        }

        iproxy_session_free(session, IPROXY_SESSION_FREE_OUT);
    }
}


void
iproxy_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_socket_t fd, struct sockaddr *sockaddr,
    int socklen, void *data)
{
    iproxy_config_t     *config;
    isshe_mempool_t     *mempool = NULL;
    iproxy_session_t    *session = NULL;
    isshe_connection_t  *out_conn = NULL;

    config = (iproxy_config_t *)data;
    isshe_debug_print_addr(sockaddr, config->log);  // DEBUG

    // TODO 实现完再进行内存使用统计，再优化这里的内存池大小。
    // 新建一个内存池(默认一页），供此连接使用
    mempool = isshe_mempool_create(getpagesize(), config->log);
    if (!mempool) {
        isshe_log_alert(config->log, "create memory pool for connection failed");
        goto iproxy_event_accept_error;
    }

    // 分配一个session
    session = isshe_mpalloc(mempool, sizeof(iproxy_session_t));
    if (!session) {
        isshe_log_alert(config->log, "malloc session failed");
        goto iproxy_event_accept_error;
    }

    // 从内存池中取两个连接
    session->inconn = isshe_connection_get(config->connpool);
    if (!session->inconn) {
        isshe_log_alert(config->log, "get inbound connection failed");
        goto iproxy_event_accept_error;
    }

    // out相关的资源先分配好，后面再使用。
    session->outconn = isshe_connection_get(config->connpool);
    if (!session->outconn) {
        isshe_log_alert(config->log, "get outbound connection failed");
        goto iproxy_event_accept_error;
    }

    // new in options
    session->inopts = isout_options_create(mempool, config->log);
    if (!session->inopts) {
        isshe_log_alert(config->log, "create isout options failed");
        goto iproxy_event_accept_error;
    }

    // new in buffer
    session->inbuf = isshe_mpalloc(mempool, ISOUT_OPTIONS_STRING_LEN_MAX);
    if (!session->inbuf) {
        goto iproxy_event_accept_error;
    }
    session->inbuf_len = ISOUT_OPTIONS_STRING_LEN_MAX;
    session->inbuf_used_len = 0;

    // new bufferevent
    session->inbev = ievent_buffer_event_socket_create(config->event, fd);
    session->outbev = ievent_buffer_event_socket_create(config->event, ISSHE_INVALID_FILE);
    if (!session->inbev || !session->outbev) {
        isshe_log_alert(config->log, "create in/out bev failed");
        goto iproxy_event_accept_error;
    }

    // 设置入口回调，读取数据
    session->mempool = mempool;
    session->config = config;
    session->inconn->fd = fd;
    session->inconn->status = ISOUT_STATUS_UNKNOWN;
    session->inconn->data = (void *)session;
    session->inconn->mempool = mempool;
    session->outconn->mempool = mempool;
    session->outconn->data = (void *)session;

    ievent_buffer_event_setcb(session->inbev, iproxy_event_in_read_cb, 
        NULL, iproxy_event_in_event_cb, (void*)session);
    ievent_buffer_event_enable(session->inbev, EV_READ|EV_WRITE);

    ievent_buffer_event_setcb(session->outbev, iproxy_event_out_read_cb, 
        NULL, iproxy_event_out_event_cb, (void*)session);
    ievent_buffer_event_enable(session->outbev, EV_READ|EV_WRITE);

    return;

iproxy_event_accept_error:
    if (session) {
        iproxy_session_free(session, IPROXY_SESSION_FREE_IN | IPROXY_SESSION_FREE_OUT);
    }
}