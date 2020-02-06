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

isshe_int_t
iproxy_event_in_transfer_data(iproxy_session_t *session)
{
    isshe_size_t        remain_len;
    isshe_size_t        stropts_len;
    isshe_log_t         *log = session->config->log;
    isshe_char_t        data[IEVENT_BUFFER_MAX_READ];
    isshe_size_t        data_len = 0;
    isshe_size_t        total_len = 0;
    isshe_size_t        read_len = 0;
    isshe_connection_t  *outconn;

    total_len = ievent_buffer_get_length(ievent_buffer_event_get_input(session->inbev));

    // 读选项阶段。inbuf_used_len != 0 表示读选项
    if (session->inconn->status == ISOUT_STATUS_READ_OPTS) {
        remain_len = session->inbuf_len - session->inbuf_used_len;
        if (remain_len <= 0) {
            isshe_log_warning(log, "isout options buffer remain lenght = 0");
            return ISSHE_FAILURE;
        }

        read_len = total_len < remain_len ? total_len : remain_len;
        read_len = ievent_buffer_event_read(session->inbev,
            session->inbuf + session->inbuf_used_len, read_len);
        
        session->inbuf_used_len += read_len;
        total_len -= read_len;

        // 检查是否是完整的选项
        stropts_len = isout_options_string_len(
            session->inbuf, session->inbuf_used_len);
        if (stropts_len == ISSHE_FAILURE) {
            // 继续等待更多数据
            isshe_log_debug(log, "iproxy in: waiting more data");
            return ISSHE_SUCCESS;
        }

        // 解析选项
        if (isout_options_from_string(session->inopts, session->inbuf,
        session->mempool, log) == ISSHE_FAILURE) {
            isshe_log_error(log, "isout options parse failed");
            return ISSHE_FAILURE;
        }

        //isout_options_print(session->inopts, log);

        // 读多了数据，复制到data
        /*
        data_len = session->inbuf_used_len - stropts_len;
        if (data_len > 0) {
            isshe_memcpy(data, session->inbuf + stropts_len, data_len);
        }
        */
        session->stropts_len = stropts_len;

        //session->inbuf_used_len = 0;
        session->inconn->status = ISOUT_STATUS_READ_DATA;
    }

    // 连接下一跳
    outconn = session->outconn;
    if (!outconn->addr_text) {
        outconn->addr_text = isshe_mpalloc(
            session->mempool, session->inopts->dname_len + 1);
        if (!outconn->addr_text) {
            isshe_log_alert(log, "mpalloc addr_text failed");
            return ISSHE_FAILURE;
        }
        isshe_memcpy(outconn->addr_text,
            session->inopts->dname,session->inopts->dname_len);
        outconn->addr_text[session->inopts->dname_len] = '\0';

        outconn->sockaddr = isshe_mpalloc(session->mempool, sizeof(isshe_sockaddr_t));
        if (!outconn->sockaddr) {
            isshe_log_alert(log, "mpalloc sockaddr failed");
            return ISSHE_FAILURE;
        }

        isshe_log_debug(log, "outconn->addr_text = (%d)%s",
            strlen(outconn->addr_text), outconn->addr_text);

        if (isshe_conn_addr_pton(outconn->addr_text,
        ISSHE_CONN_ADDR_TYPE_DOMAIN, outconn->sockaddr,
        &outconn->socklen) == ISSHE_FAILURE) {
            isshe_log_alert(log, "convert addr string to socksaddr failed");
            return ISSHE_FAILURE;
        }

        isshe_log_debug(log, "set sock port = %d", session->inopts->port);
        isshe_conn_port_set(outconn->sockaddr, session->inopts->port);

        isshe_debug_print_addr((struct sockaddr *)outconn->sockaddr, log);

        // 连接下一跳（需要的话）
        if (iproxy_event_connect_to_next(session->outbev, outconn->sockaddr,
        outconn->socklen, log) == ISSHE_FAILURE) {
            isshe_log_alert(log, "connect to xx(TODO) failed");
            return ISSHE_FAILURE;
        }
    }

    if (session->inopts->data_len <= 0) {
        session->outconn->status = ISOUT_STATUS_READ_OPTS;
        return ISSHE_SUCCESS;
    }

    // 读数据阶段
    data_len = session->inbuf_used_len - session->stropts_len;
    if (total_len + data_len < session->inopts->data_len) {
        // 没数据或者需要等待更多数据
        return ISSHE_SUCCESS;
    }

    if (data_len > 0) {
        isshe_memcpy(data, session->inbuf + session->stropts_len, data_len);
    }

    // 读取、解密、转发数据部分
    if (data_len < session->inopts->data_len) {
        ievent_buffer_event_read(session->inbev,
            data + data_len, session->inopts->data_len - data_len);
    }

    data_len = session->inopts->data_len;
    isout_decode(session->inopts, data, data_len, log);
    isshe_log_debug(log, "in(%p) -> out(%p): options len: %d, data len = %d",
        session->inbev, session->outbev, stropts_len, data_len);
    ievent_buffer_event_write(session->outbev, data, data_len);
    session->inconn->status = ISOUT_STATUS_READ_OPTS;

    session->inbuf_used_len = 0;

    return ISSHE_SUCCESS;
}


void iproxy_event_in_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    iproxy_session_t    *session = (iproxy_session_t *)ctx;

    if (iproxy_event_in_transfer_data(session) == ISSHE_FAILURE) {
        // 释放连接、释放资源
    }
}

isshe_int_t
iproxy_event_out_transfer_data(iproxy_session_t *session)
{
    isshe_log_t     *log;
    isshe_char_t    data[IEVENT_BUFFER_MAX_READ + ISOUT_OPTIONS_STRING_LEN_MAX];
    isshe_size_t    data_len = 0;
    isshe_size_t    stropts_len = 0;
    isshe_uint32_t  tmp;

    log = session->config->log;
    data_len = ievent_buffer_get_length(
        ievent_buffer_event_get_input(session->outbev));
    if (data_len == 0) {
        return ISSHE_SUCCESS;
    }

    //isshe_log_debug(log, "---isshe---: iproxy_event_out_transfer_data---1--- data_len = %d", data_len);
    // 添加选项（data_len、end)
    tmp = htonl(data_len);
    stropts_len += isout_option_append(data + stropts_len,
        ISOUT_OPTION_DATA_LEN, sizeof(isshe_uint32_t), &tmp);
    stropts_len += isout_option_append(
        data + stropts_len, ISOUT_OPTION_END, 0, NULL);

    //isout_options_print(session->inopts, log);

    //data_len = stropts_len;
    // 读取数据
    ievent_buffer_event_read(session->outbev, data + stropts_len, data_len);
    
    // 加密数据
    if (data_len) {
        isout_encode(session->inopts, data + stropts_len, data_len, log);
    }

    isshe_log_debug(log, "out(%p) -> in(%p): options len: %d, data len = %d",
        session->outbev, session->inbev, stropts_len, data_len);
    // 转发选项 & 数据
    ievent_buffer_event_write(session->inbev, data, stropts_len + data_len);

    //iproxy_event_transfer_data(session->inbev, session->outbev, log);

    return ISSHE_SUCCESS;
}

void iproxy_event_out_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    iproxy_session_t *session = (iproxy_session_t *)ctx;

    if (iproxy_event_out_transfer_data(session) == ISSHE_FAILURE) {
        // 释放资源、释放连接
    }
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
    session->inconn->status = ISOUT_STATUS_READ_OPTS;
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