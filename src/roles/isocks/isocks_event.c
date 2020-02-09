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
    ievent_buffer_event_t *srcbev, isshe_int_t  data_len, isshe_log_t *log)
{
    isshe_char_t        buf[ISSHE_DEFAULT_BUFFER_LEN] = {0};
    isshe_int_t         buf_len = ISSHE_DEFAULT_BUFFER_LEN;
    isshe_int_t         read_len = 0;
    
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
    isshe_char_t                stropts[ISOUT_PROTOCOL_OPTIONS_LEN_MAX];
    isshe_char_t                data[ISOUT_PROTOCOL_DATA_LEN_MAX];
    isshe_int_t                 data_len;
    isshe_int_t                 opts_len;
    isout_protocol_header_t     header;
    isout_protocol_options_t    opts;
    isshe_log_t                 *log;
    ievent_buffer_event_t       *src_bev;
    ievent_buffer_event_t       *dst_bev;
    ievent_buffer_t             *buffer;

    log = session->config->log;
    src_bev = session->inbev;
    dst_bev = session->outbev;
    buffer = ievent_buffer_event_get_input(src_bev);
    if (!buffer) {
        return ISSHE_FAILURE;
    }

    while(ievent_buffer_get_length(buffer) > 0) {
        // 获取数据长度
        data_len = ievent_buffer_get_length(buffer);
        //if (data_len <= 0) {
        //    return ISSHE_SUCCESS;
        //}

        // 生成选项
        //isocks_socks5_info_print(&session->socks5, log);
        isshe_memzero(&opts, sizeof(isout_protocol_options_t));
        if (isout_protocol_send_opts_generate(&opts,
        session->outopts, (isshe_addr_info_t *)(&session->socks5),
        session->mempool, log) == ISSHE_FAILURE) {
            goto isocks_event_in_td_error;
        }

        // 读取数据
        data_len = ievent_buffer_event_read(session->inbev, data, data_len);
        if (data_len == ISSHE_FAILURE) {
            isshe_log_error(log, "read data length: %d", data_len);
            goto isocks_event_in_td_error;
        }

        // 设置协议选项
        opts.data_len = data_len;       // TODO
        if (isout_protocol_options_to_string(
        &opts, stropts, &opts_len, log) == ISSHE_FAILURE) {
            isshe_log_error(log, "isout protocol options to string failed");
            goto isocks_event_in_td_error;
        }

        isout_protocol_options_print(&opts, log);

        // 设置协议头部
        isout_protocol_header_set(&header,
            (isshe_uint16_t)opts_len, (isshe_uint16_t)data_len);
        //isout_protocol_header_print(&header, log);

        // 加密协议头部、协议选项、数据
        isout_encode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
            (isshe_char_t *)&header, sizeof(header), log);
        isout_encode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
            stropts, opts_len, log);

        isout_encode(session->outopts->session_crypto_algo,
            session->outopts->session_crypto_key,
            session->outopts->session_crypto_iv, data, data_len, log);

        // 转发头部、选项、数据
        isshe_log_debug(log,
            "in(%p) -> out(%p): header len: %d, options len: %d, data len = %d",
            session->inbev, session->outbev, sizeof(header), opts_len, data_len);

        ievent_buffer_event_write(session->outbev, &header, sizeof(header));
        ievent_buffer_event_write(session->outbev, stropts, opts_len);
        ievent_buffer_event_write(session->outbev, data, data_len);
    }


    return ISSHE_SUCCESS;

isocks_event_in_td_error:
    isout_protocol_send_opts_resume(
        &opts, session->outopts, session->mempool, log);

    return ISSHE_FAILURE;
}


isshe_int_t
isocks_event_out_transfer_data(isocks_session_t *session)
{
    ievent_buffer_t             *buffer;
    isshe_log_t                 *log;
    ievent_buffer_event_t       *src_bev;
    ievent_buffer_event_t       *dst_bev;
    isshe_int_t                 header_len;
    isshe_int_t                 bev_len;
    isshe_int_t                 read_len;
    isout_protocol_header_t     header;
    isout_protocol_header_t     *phdr;
    isshe_char_t                stropts[ISOUT_PROTOCOL_OPTIONS_LEN_MAX];
    isshe_char_t                data[ISOUT_PROTOCOL_DATA_LEN_MAX];
    isout_protocol_options_t    *opts;
    isshe_connection_t          *conn;

    log = session->config->log;
    src_bev = session->outbev;
    dst_bev = session->inbev;
    opts = session->outopts;
    conn = session->outconn;
    phdr = session->outhdr;
    header_len = sizeof(isout_protocol_header_t);
    buffer = ievent_buffer_event_get_input(src_bev);
    if (!buffer) {
        return ISSHE_FAILURE;
    }

    while(ievent_buffer_get_length(buffer) > 0) {
        // 读头部
        if (conn->status == ISOUT_STATUS_UNKNOWN
        || conn->status == ISOUT_STATUS_READ_HDR) {

            conn->status = ISOUT_STATUS_READ_HDR;
            bev_len = ievent_buffer_get_length(buffer);
            if (bev_len == 0 || bev_len < header_len) {
                // 等待更多数据
                return ISSHE_SUCCESS;
            }

            read_len = ievent_buffer_event_read(
                src_bev, phdr, header_len);
            if (read_len == ISSHE_FAILURE || read_len != header_len) {
                return ISSHE_FAILURE;
            }

            if (!isout_protocol_header_is_valid(phdr)) {
                isshe_log_error(log, "invalid isout protocol header");
                return ISSHE_FAILURE;
            }

            // 解密头部
            isout_decode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
                (isshe_char_t *)phdr, header_len, log);

            conn->status = ISOUT_STATUS_READ_OPTS;
        }

        isout_protocol_header_get(&header, phdr);

        // 读选项
        if (conn->status == ISOUT_STATUS_READ_OPTS) {
            bev_len = ievent_buffer_get_length(buffer);
            if (bev_len == 0 || bev_len < header.opts_len) {
                // 等待更多数据
                return ISSHE_SUCCESS;
            }

            read_len = ievent_buffer_event_read(
                src_bev, stropts, header.opts_len);
            if (read_len == ISSHE_FAILURE || read_len != header.opts_len) {
                return ISSHE_FAILURE;
            }

            // 解析选项
            if (isout_protocol_options_from_string(opts,
            stropts, header.opts_len, session->mempool, log) == ISSHE_FAILURE) {
                isshe_log_error(log, "isout options parse failed");
                return ISSHE_FAILURE;
            }

            //isout_protocol_options_print(opts, log);

            // 解密
            isout_decode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
                stropts, header.opts_len, log);

            conn->status = ISOUT_STATUS_READ_DATA;
        }

        // 读数据
        if (conn->status == ISOUT_STATUS_READ_DATA) {
            bev_len = ievent_buffer_get_length(buffer);
            if (bev_len == 0 || bev_len < header.data_len) {
                // 等待更多数据
                return ISSHE_SUCCESS;
            }

            read_len = ievent_buffer_event_read(src_bev, data, header.data_len);
            if (read_len == ISSHE_FAILURE || read_len != header.data_len) {
                return ISSHE_FAILURE;
            }

            // 解密
            isout_decode(opts->session_crypto_algo,
                opts->session_crypto_key,
                opts->session_crypto_iv,
                data, header.data_len, log);

            isshe_log_debug(log, "out(%p) -> in(%p): data = (%d)",
                src_bev, dst_bev, header.data_len);

            // 转发数据
            ievent_buffer_event_write(dst_bev, data, header.data_len);

            conn->status = ISOUT_STATUS_READ_HDR;
            //isshe_memzero(phdr, header_len);  // 用完清零
        }
    }


    return ISSHE_SUCCESS;
}

void isocks_event_in_read_cb(ievent_buffer_event_t *bev, void *ctx)
{
    isocks_session_t    *session = (isocks_session_t *)ctx;
    isshe_connection_t  *inconn;
    isshe_log_t         *log;
    isshe_int_t         ret;

    log = session->config->log;

    session->read_count++;      // TODO debug

    inconn = session->inconn;
    if (!inconn) {
        isshe_log_warning(log, "in read callback, but connection == NULL");
        return;
    }

    switch (inconn->status)
    {
    case SOCKS5_STATUS_CONNECTED:
        //isocks_socks5_info_print(&session->socks5, log);
        isocks_event_in_transfer_data(session);
        break;
    case SOCKS5_STATUS_WAITING_SELECTION:
        ret = socks5_selction_message_process(bev, log);
        if (ret == ISSHE_FAILURE) {
            isshe_log_error(log, "socks5_selction_message_process failed!!!");
            isocks_session_free(session,
                ISOCKS_SESSION_FREE_IN | ISOCKS_SESSION_FREE_OUT);
            return;
        } else if (ret == ISSHE_RETRY) {
            return ;
        } else {
            inconn->status = SOCKS5_STATUS_WAITING_REQUEST;
        }

        break;
    case SOCKS5_STATUS_WAITING_REQUEST:
        ret = socks5_request_process(
            bev, session->inconn,log, &session->socks5);
        if (ret == ISSHE_FAILURE) {
            isshe_log_error(log, "socks5_request_process failed!!!");
            isocks_session_free(session,
                ISOCKS_SESSION_FREE_IN | ISOCKS_SESSION_FREE_OUT);
            return;
        } else if (ret == ISSHE_RETRY) {
            return;
        } else {
            inconn->status = SOCKS5_STATUS_CONNECTED;
        }
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
        exit(0);
    }
}


void isocks_event_in_event_cb(
    ievent_buffer_event_t *bev, short what, void *ctx)
{
    isocks_session_t        *session = (isocks_session_t *)ctx;
    isshe_log_t             *log;
    ievent_buffer_event_t   *partner;
    isshe_int_t             len;

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

            // partner发送过来的数据全部转发
            isocks_event_out_read_cb(partner, ctx);
            /*
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, IEVENT_READ);
            } else {
                // free partner
                isocks_session_free(session, ISOCKS_SESSION_FREE_OUT);
            }
            */
            isocks_session_free(session, ISOCKS_SESSION_FREE_OUT);
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
    isshe_int_t             len;

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

            // partner发送过来的数据全部转发
            isocks_event_in_read_cb(partner, ctx);
            /*
            len = ievent_buffer_get_length(ievent_buffer_event_get_output(partner));
            if (len) {
                ievent_buffer_event_disable(partner, IEVENT_READ);
            } else {
                // free partner
                isocks_session_free(session, ISOCKS_SESSION_FREE_IN);
            }
            */
            isocks_session_free(session, ISOCKS_SESSION_FREE_IN);
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
    //isshe_debug_print_addr(sockaddr, config->log);  // DEBUG

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

    session->outhdr = isout_protocol_header_create(mempool, config->log);
    if (!session->outhdr) {
        isshe_log_alert(config->log, "create isout header failed");
        goto isocks_event_accept_error;
    }

    session->outopts = isout_protocol_options_create(mempool, config->log);
    if (!session->outopts) {
        isshe_log_alert(config->log, "create isout options failed");
        goto isocks_event_accept_error;
    }

    // new bufferevent
    session->inbev = ievent_buffer_event_socket_create(config->event, fd);
    session->outbev = ievent_buffer_event_socket_create(config->event, ISSHE_INVALID_FILE);
    if (!session->inbev || !session->outbev) {
        isshe_log_alert(config->log, "create in/out bev failed");
        goto isocks_event_accept_error;
    }

    isshe_log_debug(config->log, "created: inbev: %p, outbev: %p",
        session->inbev, session->outbev);

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
    session->outconn->status = ISOUT_STATUS_UNKNOWN;
    session->read_count = 0;    // TODO debug

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