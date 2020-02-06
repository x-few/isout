#include "isocks.h"


isshe_int_t
isocks_event_transfer_data(ievent_buffer_event_t *dstbev,
    ievent_buffer_event_t *srcbev, isshe_log_t *log)
{
    ievent_buffer_t *src, *dst;

    src = ievent_buffer_event_get_input(srcbev);
    dst = ievent_buffer_event_get_output(dstbev);

    isshe_log_debug(log, "isocks transfer: %p(%u) -> %p(%lu)",
        srcbev, ievent_buffer_get_length(src),
        dstbev, ievent_buffer_get_length(dst));

    ievent_buffer_add_buffer(dst, src);

    return ISSHE_SUCCESS;
}

isshe_int_t
isocks_event_transfer_data2(ievent_buffer_event_t *dstbev,
    ievent_buffer_event_t *srcbev, isshe_size_t data_len, isshe_log_t *log)
{
    isshe_char_t        buf[ISSHE_DEFAULT_BUFFER_LEN] = {0};
    isshe_size_t        buf_len = ISSHE_DEFAULT_BUFFER_LEN;
    isshe_size_t        read_len = 0;
    
    isshe_log_debug(log, "isocks transfer: %p -> %p: %u",
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
isocks_event_in_transfer_data(isocks_session_t *session)
{
    isshe_char_t    *stropts = NULL;
    isshe_log_t     *log = session->config->log;
    isshe_char_t    data[IEVENT_BUFFER_MAX_READ + ISOUT_OPTIONS_STRING_LEN_MAX];
    isshe_size_t    data_len = 0;
    isshe_size_t    stropts_len = 0;
    isshe_uint16_t  port;
    isshe_char_t    *key;
    isshe_char_t    *iv;

    // 添加选项
    if (!session->outopts->dname) {
        session->outopts->dname = session->socks5.addr_text;
        session->outopts->dname_len = session->socks5.addr_len;
        session->outopts->port = session->socks5.port;
        
        stropts_len += isout_option_append(
            data + stropts_len, ISOUT_OPTION_DOMAIN,
            session->outopts->dname_len, session->outopts->dname);

        port = htons(session->outopts->port);
        stropts_len += isout_option_append(
            data + stropts_len, ISOUT_OPTION_PORT,
            sizeof(session->outopts->port), &port);
    }

    if (!session->outopts->session_crypto_key) {
        key = isshe_mpalloc(session->mempool, ISSHE_AES_BLOCK_SIZE);
        iv = isshe_mpalloc(session->mempool, ISSHE_AES_BLOCK_SIZE);
        if (!key || !iv) {
            isshe_log_error(log, "mpalloc key or iv failed");
            return ISSHE_FAILURE;
        }
        session->outopts->session_crypto_algo = ISOUT_CRYPTO_ALGO_AES_128_CFB;
        session->outopts->session_crypto_key = key;
        session->outopts->session_crypto_iv = iv;

        stropts_len += isout_option_append(
            data + stropts_len, ISOUT_OPTION_SESSION_CRYPTO_ALGO,
            sizeof(session->outopts->session_crypto_algo),
            &session->outopts->session_crypto_algo);
        stropts_len += isout_option_append(
            data + stropts_len, ISOUT_OPTION_SESSION_CRYPTO_KEY,
            ISSHE_AES_BLOCK_SIZE, key);
        stropts_len += isout_option_append(
            data + stropts_len, ISOUT_OPTION_SESSION_CRYPTO_IV,
            ISSHE_AES_BLOCK_SIZE, iv);
    }

    //session->outopts->data_len = strlen("isshechudai");
    session->outopts->data_len = ievent_buffer_get_length(
        ievent_buffer_event_get_input(session->inbev));
    if (session->outopts->data_len == 0) {
        return ISSHE_SUCCESS;
    }

    data_len = htonl(session->outopts->data_len);

    stropts_len += isout_option_append(
        data + stropts_len, ISOUT_OPTION_DATA_LEN,
        sizeof(session->outopts->data_len), &data_len);

    stropts_len += isout_option_append(
        data + stropts_len, ISOUT_OPTION_END, 0, NULL);

    data_len = session->outopts->data_len;

    //isout_options_print(session->outopts, log);

    // 读取数据
    ievent_buffer_event_read(session->inbev, data + stropts_len, data_len);
    
    //isshe_memcpy(data + stropts_len, "isshechudai", data_len);
    // 加密数据
    if (data_len != 0) {
        isout_encode(session->outopts, data + stropts_len, data_len, log);
    }

    // 转发选项 & 数据
    isshe_log_debug(log, "in(%p) -> out(%p): options len: %d, data len = %d",
        session->inbev, session->outbev, stropts_len, data_len);
    ievent_buffer_event_write(session->outbev, data, stropts_len + data_len);

    return ISSHE_SUCCESS;
}

/*
 * 1. 目标数据 >= 头部 + 数据：1次回调。
 * 2. 目标数据 < 头部：
 *  2.1 目标数据 >= 头部+数据：2次回调
 *  2.2 目标数据 > 头部 && < 数据：3次回调
 * 3. 目标数据 > 头部 && 目标数据 < 数据：两次回调。
 */
isshe_int_t
isocks_event_out_transfer_data(isocks_session_t *session)
{
    isshe_size_t    remain_len = 0;
    isshe_size_t    stropts_len = 0;
    isshe_log_t     *log = session->config->log;
    isshe_char_t    data[IEVENT_BUFFER_MAX_READ];
    isshe_size_t    data_len = 0;
    isshe_size_t    total_len = 0;
    isshe_size_t    read_len = 0;

    total_len = ievent_buffer_get_length(
        ievent_buffer_event_get_input(session->outbev));

    // 读选项阶段。outbuf_used_len != 0 表示读选项
    if (session->outconn->status == ISOUT_STATUS_READ_OPTS) {
        // 
        remain_len = session->outbuf_len - session->outbuf_used_len;
        if (remain_len <= 0) {
            isshe_log_warning(log, "isout options buffer remain lenght = %d", remain_len);
            return ISSHE_FAILURE;   // 释放关闭连接
        }

        read_len = total_len < remain_len ? total_len : remain_len;
        read_len = ievent_buffer_event_read(session->outbev,
            session->outbuf + session->outbuf_used_len, read_len);

        session->outbuf_used_len += read_len;
        total_len -= read_len;

        // 检查是否是完整的选项
        stropts_len = isout_options_string_len(
            session->outbuf, session->outbuf_used_len);
        if (stropts_len == ISSHE_FAILURE) {
            // 继续等待更多数据
            return ISSHE_SUCCESS;
        }

        // 解析选项
        if (isout_options_from_string(
            session->outopts, session->outbuf,
            session->mempool, log) == ISSHE_FAILURE) {
            
            isshe_log_warning(log, "isout options parse failed");
            return ISSHE_FAILURE;
        }

        //isout_options_print(session->outopts, log);

        // 读多了数据，复制到data
        //data_len = session->outbuf_used_len - stropts_len;
        //if (data_len > 0) {
        session->stropts_len = stropts_len;
            //isshe_memcpy(data, session->outbuf + stropts_len, data_len);
        //}

        //session->outbuf_used_len = data_len;
        session->outconn->status = ISOUT_STATUS_READ_DATA;
    }

    if (session->outopts->data_len <= 0) {
        isshe_log_warning(log, "session->outopts->data_len = %d", session->outopts->data_len);
        session->outconn->status = ISOUT_STATUS_READ_OPTS;
        return ISSHE_SUCCESS;
    }

    // 读数据阶段
    data_len = session->outbuf_used_len - session->stropts_len;
    if (total_len + data_len < session->outopts->data_len) {
        // 没数据或者需要等待更多数据
        return ISSHE_SUCCESS;
    }

    if (data_len > 0) {
        isshe_memcpy(data, session->outbuf + session->stropts_len, data_len);
    }

    // 读取、解密、转发数据部分
    if (data_len < session->outopts->data_len) {
        ievent_buffer_event_read(session->outbev,
            data + data_len, session->outopts->data_len - data_len);
    }

    data_len = session->outopts->data_len;
    isout_decode(session->outopts, data, data_len, log);

    isshe_log_debug(log, "out(%p) -> in(%p): options len: %d, data len = %d",
        session->outbev, session->inbev, stropts_len, data_len);

    ievent_buffer_event_write(session->inbev, data, data_len);

    //isocks_event_transfer_data(session->inbev,
    //    session->outbev, session->config->log);

    session->outconn->status = ISOUT_STATUS_READ_OPTS;
    session->outbuf_used_len = 0;

    return ISSHE_SUCCESS;
}

void isocks_event_in_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    isocks_session_t    *session = (isocks_session_t *)ctx;
    isshe_connection_t  *inconn;
    isshe_log_t         *log;

    log = session->config->log;

    inconn = session->inconn;
    if (!inconn) {
        isshe_log_warning(log, "in read callback, but connection == NULL");
        return;
    }

    switch (inconn->status)
    {
    case SOCKS5_STATUS_CONNECTED:
        isocks_event_in_transfer_data(session);
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

    if (isocks_event_out_transfer_data(session) == ISSHE_FAILURE) {
        // TODO 禁用读写、关闭、释放连接
    }
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

	if (what & (IEVENT_BEV_EVENT_EOF|IEVENT_BEV_EVENT_ERROR)) {
        if (what & IEVENT_BEV_EVENT_ERROR) {
            if (errno) {
                isshe_log_alert_errno(log, errno, "in connection error, bev = %p", bev);
            } else {
                isshe_log_alert(log, "in connection error, bev = %p", bev);
            }
        }

        if (partner) {
            // 把所有数据读出来，发给partner
            isocks_event_in_read_cb(bev, ctx);
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, IEVENT_READ);
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

	if (what & (IEVENT_BEV_EVENT_EOF|IEVENT_BEV_EVENT_ERROR)) {
        if (what & IEVENT_BEV_EVENT_ERROR) {
            if (errno) {
                isshe_log_alert_errno(log, errno, "out connection error");
            }
        }

        if (partner) {
            // 把所有数据读出来，发给partner
            isocks_event_out_read_cb(bev, ctx);
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, IEVENT_READ);
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

    return ISSHE_SUCCESS;
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

    session->outopts = isout_options_create(mempool, config->log);
    if (!session->outopts) {
        isshe_log_alert(config->log, "create isout options failed");
        goto isocks_event_accept_error;
    }

    session->outbuf = isshe_mpalloc(mempool, ISOUT_OPTIONS_STRING_LEN_MAX);
    if (!session->outbuf) {
        goto isocks_event_accept_error;
    }
    session->outbuf_len = ISOUT_OPTIONS_STRING_LEN_MAX;
    session->outbuf_used_len = 0;

    // new bufferevent
    session->inbev = ievent_buffer_event_socket_create(config->event, fd);
    session->outbev = ievent_buffer_event_socket_create(config->event, ISSHE_INVALID_FILE);
    if (!session->inbev || !session->outbev) {
        isshe_log_alert(config->log, "create in/out bev failed");
        goto isocks_event_accept_error;
    }

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
    session->outconn->status = ISOUT_STATUS_READ_OPTS;

    ievent_buffer_event_setcb(session->inbev, isocks_event_in_read_cb, 
        NULL, isocks_event_in_event_cb, (void*)session); //->outconn);
    ievent_buffer_event_enable(session->inbev, IEVENT_READ|EV_WRITE);
    ievent_buffer_event_setcb(session->outbev, isocks_event_out_read_cb, 
        NULL, isocks_event_out_event_cb, (void*)session); //->inconn);
    ievent_buffer_event_enable(session->outbev, IEVENT_READ|EV_WRITE);

    return;

isocks_event_accept_error:
    if (session) {
        isocks_session_free(session, ISOCKS_SESSION_FREE_IN | ISOCKS_SESSION_FREE_OUT);
    }

    // TODO 怎么关闭连接？
    // ievent_connection_close(fd);
}