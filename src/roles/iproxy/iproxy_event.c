#include "iproxy.h"

static isshe_void_t iproxy_event_out_read_cb(
    ievent_buffer_event_t *bev, isshe_void_t *ctx);
static isshe_void_t iproxy_event_out_event_cb(
    ievent_buffer_event_t *bev, isshe_short_t what, isshe_void_t *ctx);
static isshe_void_t iproxy_event_out_write_cb(
    ievent_buffer_event_t *bev, isshe_void_t *ctx);
static isshe_void_t iproxy_event_in_read_cb(
    ievent_buffer_event_t *bev, isshe_void_t *ctx);
static isshe_void_t iproxy_event_in_event_cb(
    ievent_buffer_event_t *bev, isshe_short_t what, isshe_void_t *ctx);
static isshe_void_t iproxy_event_in_write_cb(
    ievent_buffer_event_t *bev, isshe_void_t *ctx);

static isshe_int_t
iproxy_event_connect_to_next(
    ievent_buffer_event_t *bev,
    isshe_sockaddr_t *sockaddr,
    isshe_socklen_t socklen, isshe_log_t *log)
{
    if (ievent_buffer_event_socket_connect(bev, sockaddr, socklen) < 0) {
        isshe_log_alert_errno(log, errno, "connect to xxx failed");
        return ISSHE_ERROR;
    }

    return ISSHE_OK;
}


// TODO 区分地址类型
isshe_int_t
iproxy_connect_to_out(iproxy_session_t *session,
    isshe_connection_t *outconn, isshe_log_t *log)
{
    isout_protocol_options_t    *opts;

    if (!session || !outconn) {
        isshe_log_error(log, "to out failed: invalid parameters");
        return ISSHE_ERROR;
    }

    // 连接下一跳
    if (!outconn->addr) {
        opts = session->inopts;
        outconn->addr = isshe_address_create(opts->addr,
            opts->addr_len, opts->addr_type, session->mempool, log);
        if (!outconn->addr) {
            isshe_log_error(log, "isshe_address_create failed");
            return ISSHE_ERROR;
        }
        if (!isshe_address_sockaddr_create(
            outconn->addr, session->mempool, log)) {
            isshe_log_error(log, "isshe_address_sockaddr_create failed");
            return ISSHE_ERROR;
        }

        isshe_address_port_set(outconn->addr, opts->port);

        isshe_debug_print_addr((isshe_sa_t *)outconn->addr->sockaddr, log);

        // 连接下一跳（需要的话）
        if (iproxy_event_connect_to_next(
        session->outbev, outconn->addr->sockaddr,
        outconn->addr->socklen, log) == ISSHE_ERROR) {
            isshe_log_alert(log, "connect to xx(TODO) failed");
            return ISSHE_ERROR;
        }
    }
    
    return ISSHE_OK;
}

isshe_int_t
iproxy_event_in_transfer_data(iproxy_session_t *session)
{
    ievent_buffer_t             *src_buffer, *dst_buffer;
    isshe_log_t                 *log;
    ievent_buffer_event_t       *src_bev;
    ievent_buffer_event_t       *dst_bev;
    isshe_int_t                 header_len;
    isshe_int_t                 bev_len;
    isshe_int_t                 read_len;
    isout_protocol_header_t     header;
    isshe_char_t                stropts[ISOUT_PROTOCOL_OPTIONS_LEN_MAX];
    isshe_char_t                data[ISOUT_PROTOCOL_DATA_LEN_MAX];
    isout_protocol_header_t     *phdr;
    isout_protocol_options_t    *opts;
    isshe_connection_t          *conn;

    log = session->config->log;
    src_bev = session->inbev;
    dst_bev = session->outbev;
    opts = session->inopts;
    conn = session->inconn;
    phdr = session->inhdr;
    header_len = sizeof(isout_protocol_header_t);
    src_buffer = ievent_buffer_event_get_input(src_bev);
    dst_buffer = ievent_buffer_event_get_output(dst_bev);
    if (!src_buffer || !dst_buffer) {
        isshe_log_error(log, "get input/output buffer failed");
        return ISSHE_ERROR;
    }

    while(ievent_buffer_get_length(src_buffer) > 0) {
        // 读头部
        if (conn->status == ISOUT_STATUS_UNKNOWN
        || conn->status == ISOUT_STATUS_READ_HDR) {

            conn->status = ISOUT_STATUS_READ_HDR;
            bev_len = ievent_buffer_get_length(src_buffer);
            if (bev_len == 0 || bev_len < header_len) {
                // 等待更多数据
                return ISSHE_OK;
            }

            read_len = ievent_buffer_event_read(
                src_bev, phdr, header_len);
            if (read_len == ISSHE_ERROR || read_len != header_len) {
                isshe_log_error(log, "read isout header failed");
                return ISSHE_ERROR;
            }

            if (!isout_protocol_header_is_valid(phdr)) {
                //isout_protocol_header_print(phdr, log);
                isshe_log_error(log, "invalid isout protocol header");
                return ISSHE_ERROR;
            }

            // 解密头部
            isout_decode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
                (isshe_char_t *)phdr, header_len, log);

            conn->status = ISOUT_STATUS_READ_OPTS;
        }

        isout_protocol_header_get(&header, phdr);

        // 读选项
        if (conn->status == ISOUT_STATUS_READ_OPTS) {
            bev_len = ievent_buffer_get_length(src_buffer);
            if (bev_len == 0 || bev_len < header.opts_len) {
                // 等待更多数据
                return ISSHE_OK;
            }

            read_len = ievent_buffer_event_read(
                src_bev, stropts, header.opts_len);
            if (read_len == ISSHE_ERROR || read_len != header.opts_len) {
                isshe_log_error(log, "read isout options failed");
                return ISSHE_ERROR;
            }

            // 解析选项
            if (isout_protocol_options_from_string(opts,
            stropts, header.opts_len, session->mempool, log) == ISSHE_ERROR) {
                isshe_log_error(log, "isout options parse failed");
                return ISSHE_ERROR;
            }

            isout_protocol_options_print(opts, log);

            // 解密
            isout_decode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
                stropts, header.opts_len, log);

            conn->status = ISOUT_STATUS_READ_DATA;
        }

        // 连接下一跳
        if (iproxy_connect_to_out(
        session, session->outconn, log) == ISSHE_ERROR) {
            isshe_log_warning(log, "connect to out failed!!!");
            return ISSHE_ERROR;
        }

        // 读数据
        if (conn->status == ISOUT_STATUS_READ_DATA) {
            bev_len = ievent_buffer_get_length(src_buffer);
            if (bev_len == 0 || bev_len < header.data_len) {
                // 等待更多数据
                return ISSHE_OK;
            }

            read_len = ievent_buffer_event_read(src_bev, data, header.data_len);
            if (read_len == ISSHE_ERROR || read_len != header.data_len) {
                isshe_log_error(log, "read isout header failed");
                return ISSHE_ERROR;
            }

            // 解密
            isout_decode(opts->session_crypto_algo,
                opts->session_crypto_key,
                opts->session_crypto_iv,
                data, header.data_len, log);

            // 转发数据
            isshe_log_debug(log, "in(%p) -> out(%p): data = (%d)",
                src_bev, dst_bev, header.data_len);
            ievent_buffer_event_write(dst_bev, data, header.data_len);

            conn->status = ISOUT_STATUS_READ_HDR;
            //isshe_memzero(phdr, header_len);  // 用完清零
            session->inbytes += header.data_len;

            if (ievent_buffer_get_length(dst_buffer) >= IEVENT_OUTPUT_BUFFER_MAX) {
                // 太多数据积压了，停止读
                ievent_buffer_event_setcb(dst_bev,
                    iproxy_event_out_read_cb,
                    iproxy_event_out_write_cb,
                    iproxy_event_out_event_cb, (isshe_void_t *)session);
                ievent_buffer_event_water_mark_set(dst_bev, IEVENT_WRITE,
                    IEVENT_OUTPUT_BUFFER_MAX/2, IEVENT_OUTPUT_BUFFER_MAX);
                ievent_buffer_event_disable(src_bev, IEVENT_READ);
                break; // TODO 考虑这个while，准备去掉
            }
        }
    }


    return ISSHE_OK;
}


isshe_void_t iproxy_event_in_read_cb(ievent_buffer_event_t *bev, isshe_void_t *ctx)
{
    iproxy_session_t    *session = (iproxy_session_t *)ctx;

    if (iproxy_event_in_transfer_data(session) == ISSHE_ERROR) {
        // 释放连接、释放资源
        iproxy_session_free(session,
            IPROXY_SESSION_FREE_IN | IPROXY_SESSION_FREE_OUT);
    }
}

isshe_int_t
iproxy_event_out_transfer_data(iproxy_session_t *session)
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
    ievent_buffer_t             *src_buffer, *dst_buffer;

    log = session->config->log;
    src_bev = session->outbev;
    dst_bev = session->inbev;

    src_buffer = ievent_buffer_event_get_input(src_bev);
    dst_buffer = ievent_buffer_event_get_output(dst_bev);
    if (!src_buffer || !dst_buffer) {
        isshe_log_error(log, "get input src_buffer failed");
        return ISSHE_ERROR;
    }

    while(ievent_buffer_get_length(src_buffer) > 0) {
        // 获取数据长度
        data_len = ievent_buffer_get_length(src_buffer);
        /*
        if (data_len <= 0) {
            return ISSHE_OK;
        }
        */

        // 读取数据
        data_len = ievent_buffer_event_read(src_bev, data, data_len);
        if (data_len == ISSHE_ERROR) {
            isshe_log_error(log, "read data length: %d", data_len);
            return ISSHE_ERROR;
        }

        // 设置协议选项
        isshe_memzero(&opts, sizeof(isout_protocol_options_t));
        opts.data_len = data_len;
        if (isout_protocol_options_to_string(
        &opts, stropts, &opts_len, log) == ISSHE_ERROR) {
            isshe_log_error(log, "isout protocol options to string failed");
            return ISSHE_ERROR;
        }

        // 设置协议头部
        isout_protocol_header_set(&header,
            (isshe_uint16_t)opts_len, (isshe_uint16_t)data_len);
        //isout_protocol_header_print(&header, log);

        // 加密协议头部、协议选项、数据
        isout_encode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
            (isshe_char_t *)&header, sizeof(header), log);
        isout_encode(ISOUT_CRYPTO_ALGO_UNKNOWN, NULL, NULL,
            stropts, opts_len, log);

        isout_encode(session->inopts->session_crypto_algo,
            session->inopts->session_crypto_key,
            session->inopts->session_crypto_iv, data, data_len, log);

        // 转发头部、选项、数据
        isshe_log_debug(log,
            "out(%p) -> in(%p): header len: %d, options len: %d, data len = %d",
            src_bev, dst_bev, sizeof(header), opts_len, data_len);

        ievent_buffer_event_write(dst_bev, &header, sizeof(header));
        ievent_buffer_event_write(dst_bev, stropts, opts_len);
        ievent_buffer_event_write(dst_bev, data, data_len);
        session->outbytes += data_len;
        isshe_log_debug(log, "---isshe----outbytes = %ud", session->outbytes);

        if (ievent_buffer_get_length(dst_buffer) >= IEVENT_OUTPUT_BUFFER_MAX) {
            // 太多数据积压了，停止读
            ievent_buffer_event_setcb(dst_bev,
                iproxy_event_in_read_cb,
                iproxy_event_in_write_cb,
                iproxy_event_in_event_cb, (isshe_void_t *)session);
            ievent_buffer_event_water_mark_set(dst_bev, IEVENT_WRITE,
                IEVENT_OUTPUT_BUFFER_MAX/2, IEVENT_OUTPUT_BUFFER_MAX);
            ievent_buffer_event_disable(src_bev, IEVENT_READ);
            break; // TODO 考虑这个while，准备去掉
        }
    }

    return ISSHE_OK;
}


static isshe_void_t
iproxy_event_out_read_cb(ievent_buffer_event_t *bev, isshe_void_t *ctx)
{
    iproxy_session_t *session = (iproxy_session_t *)ctx;

    if (iproxy_event_out_transfer_data(session) == ISSHE_ERROR) {
        // 释放资源、释放连接
        isshe_log_alert(session->config->log, "iproxy_event_out_read_cb error!!!");
        iproxy_session_free(session,
            IPROXY_SESSION_FREE_IN | IPROXY_SESSION_FREE_OUT);
    }
}

static isshe_void_t
iproxy_event_in_write_cb(ievent_buffer_event_t *bev, isshe_void_t *ctx)
{
    iproxy_session_t *session = (iproxy_session_t *)ctx;
    ievent_buffer_event_t *partner;

    partner = session->outbev;

    ievent_buffer_event_setcb(bev, 
        iproxy_event_in_read_cb, NULL,
        iproxy_event_in_event_cb, ctx);
    ievent_buffer_event_water_mark_set(bev, IEVENT_WRITE, 0, 0);
    if (partner) {
        ievent_buffer_event_enable(partner, IEVENT_READ);
    }
}

static isshe_void_t
iproxy_event_out_write_cb(ievent_buffer_event_t *bev, isshe_void_t *ctx)
{
    iproxy_session_t *session = (iproxy_session_t *)ctx;
    ievent_buffer_event_t *partner;

    partner = session->inbev;

    ievent_buffer_event_setcb(bev, 
        iproxy_event_out_read_cb, NULL,
        iproxy_event_out_event_cb, ctx);
    ievent_buffer_event_water_mark_set(bev, IEVENT_WRITE, 0, 0);
    if (partner) {
        ievent_buffer_event_enable(partner, IEVENT_READ);
    }
}


isshe_void_t iproxy_event_in_event_cb(
    ievent_buffer_event_t *bev, isshe_short_t what, isshe_void_t *ctx)
{
    iproxy_session_t        *session = (iproxy_session_t *)ctx;
    isshe_log_t             *log;
    ievent_buffer_event_t   *partner;

    log = session->config->log;
    partner = session->outbev;

    isshe_log_debug(log, "---iproxy_event_in_event_cb---bev = %p", bev);

    assert(bev == session->inbev);

    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno) {
                isshe_log_alert_errno(log, errno, "in connection error, bev = %p", bev);
            } else {
                isshe_log_alert(log, "in connection error, bev = %p", bev);
            }
        }

        if (partner) {
            // 把所有数据读出来，发给partner
            iproxy_event_in_read_cb(bev, ctx);
            
            // partner发送过来的数据全部转发
            iproxy_event_out_read_cb(partner, ctx);

            iproxy_session_free(session, IPROXY_SESSION_FREE_OUT);
        }

        iproxy_session_free(session, IPROXY_SESSION_FREE_IN);
    }
}

static isshe_void_t iproxy_event_out_event_cb(
    ievent_buffer_event_t *bev, isshe_short_t what, isshe_void_t *ctx)
{
    iproxy_session_t        *session = (iproxy_session_t *)ctx;
    isshe_log_t             *log;
    ievent_buffer_event_t   *partner;

    log = session->config->log;
    partner = session->inbev;

    isshe_log_debug(log, "---iproxy_event_out_event_cb---bev = %p", bev);

    assert(bev == session->outbev);

    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno) {
                isshe_log_alert_errno(log, errno, "out connection error, bev = %p", bev);
            } else {
                isshe_log_alert(log, "out connection error, bev = %p", bev);
            }
        }

        if (partner) {
            // 把所有数据读出来，发给partner
            iproxy_event_out_read_cb(bev, ctx);

            // partner发送过来的数据全部转发
            iproxy_event_in_read_cb(partner, ctx);

            iproxy_session_free(session, IPROXY_SESSION_FREE_IN);

        }

        iproxy_session_free(session, IPROXY_SESSION_FREE_OUT);
    }
}


isshe_void_t
iproxy_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_fd_t fd, isshe_sa_t *sockaddr,
    int socklen, isshe_void_t *data)
{
    iproxy_config_t     *config;
    isshe_mempool_t     *mempool = NULL;
    iproxy_session_t    *session = NULL;
    isshe_connection_t  *out_conn = NULL;

    config = (iproxy_config_t *)data;
    //isshe_debug_print_addr(sockaddr, config->log);  // DEBUG

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

    isshe_memzero(session, sizeof(isocks_session_t));

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

    // new in isout header
    session->inhdr = isout_protocol_header_create(mempool, config->log);
    if (!session->inhdr) {
        isshe_log_alert(config->log, "create isout header failed");
        goto iproxy_event_accept_error;
    }

    // new in options
    session->inopts = isout_protocol_options_create(mempool, config->log);
    if (!session->inopts) {
        isshe_log_alert(config->log, "create isout options failed");
        goto iproxy_event_accept_error;
    }

    // new bufferevent
    session->inbev = ievent_buffer_event_socket_create(config->event, fd);
    session->outbev = ievent_buffer_event_socket_create(config->event, ISSHE_INVALID_FILE);
    if (!session->inbev || !session->outbev) {
        isshe_log_alert(config->log, "create in/out bev failed");
        goto iproxy_event_accept_error;
    }

    isshe_log_debug(config->log, "created: inbev: %p, outbev: %p",
        session->inbev, session->outbev);

    // 设置入口回调，读取数据
    session->mempool = mempool;
    session->config = config;
    session->inconn->fd = fd;
    session->inconn->status = ISOUT_STATUS_UNKNOWN;
    session->inconn->data = (isshe_void_t *)session;
    session->inconn->mempool = mempool;
    session->outconn->mempool = mempool;
    session->outconn->data = (isshe_void_t *)session;

    ievent_buffer_event_setcb(session->inbev, iproxy_event_in_read_cb, 
        NULL, iproxy_event_in_event_cb, (isshe_void_t*)session);
    ievent_buffer_event_enable(session->inbev, EV_READ|EV_WRITE);

    ievent_buffer_event_setcb(session->outbev, iproxy_event_out_read_cb, 
        NULL, iproxy_event_out_event_cb, (isshe_void_t*)session);
    ievent_buffer_event_enable(session->outbev, EV_READ|EV_WRITE);

    return;

iproxy_event_accept_error:
    if (session) {
        iproxy_session_free(session, IPROXY_SESSION_FREE_IN | IPROXY_SESSION_FREE_OUT);
    }
}