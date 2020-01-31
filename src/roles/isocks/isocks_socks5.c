
#include "isocks.h"

static isshe_bool_t
is_valid_socks5_selection_request(isocks_socks5_selection_request_t *request)
{
    if (request->version != ISOCKS_DEFAULT_SOCKS_VERSION) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}

static isshe_bool_t
is_valid_socks5_request(isocks_socks5_request_t *request)
{
    if (request->version != ISOCKS_DEFAULT_SOCKS_VERSION) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}

isshe_int_t
socks5_selction_message_process(ievent_buffer_event_t *bev, isshe_log_t *log)
{
    isshe_size_t                        len;
    isocks_socks5_selection_request_t   request;
    isocks_socks5_selection_reply_t     reply;

    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < sizeof(isocks_socks5_selection_request_t)) {
        // 等待更多数据
        isshe_log_debug(log,
            "waiting for more socks5 selection request data: expect %d, got %d",
            sizeof(isocks_socks5_selection_request_t), len);
        return ISSHE_SUCCESS;
    }

    ievent_buffer_event_read(bev, &request, sizeof(isocks_socks5_selection_request_t));
    if (!is_valid_socks5_selection_request(&request)) {
        isshe_log_warning(log, "got invalid socks5 request");
        return ISSHE_FAILURE;
    }

    isshe_memzero(&reply, sizeof(isocks_socks5_selection_reply_t));
    reply.version = ISOCKS_DEFAULT_SOCKS_VERSION;
    ievent_buffer_event_write(bev, &reply, sizeof(isocks_socks5_selection_reply_t));
    return ISSHE_SUCCESS;
}


isshe_int_t
socks5_connect_cmd_process(ievent_buffer_event_t *bev,
    isocks_socks5_request_t *request, isshe_connection_t *conn,
    isshe_log_t *log, isocks_socks5_info_t *info)
{
    isshe_mempool_t         *mempool = conn->mempool;
    isocks_socks5_reply_t   reply;
    isshe_size_t            len;

    // request cmd
    isshe_log_debug(log, "socks5 request addr type = %d", request->atype);
    switch (request->atype)
    {
        case ISOCKS_SOCKS5_ADDR_TYPE_DOMAIN:
            ievent_buffer_event_read(bev, &info->addr_len, sizeof(info->addr_len));
            break;
        case ISOCKS_SOCKS5_ADDR_TYPE_IPV4:
            info->addr_len = ISSHE_IPV4_ADDR_LEN;
            break;
        case ISOCKS_SOCKS5_ADDR_TYPE_IPV6:
            info->addr_len = ISSHE_IPV6_ADDR_LEN;
            break;
        default:
            isshe_log_warning(log, "unsupported sock5 addr type");
            return ISSHE_FAILURE;
    }
    info->addr_type = request->atype;
    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < info->addr_len + sizeof(info->port)) {
        isshe_log_warning(log, "expect len %d, got len %d",
            info->addr_len + sizeof(info->port), len);
        return ISSHE_FAILURE;
    }
    info->addr_text = (isshe_char_t *)isshe_mpalloc(mempool, info->addr_len);
    if (!info->addr_text) {
        isshe_log_alert(log, "mpalloc socks5 addr_text failed");
        return ISSHE_FAILURE;
    }

    ievent_buffer_event_read(bev, info->addr_text, info->addr_len);
    ievent_buffer_event_read(bev, &info->port, sizeof(info->port));
    // TODO IPv4 ntohs
    info->port = ntohs(info->port);

    // reply
    isshe_memzero(&reply, sizeof(isocks_socks5_reply_t));
    reply.version = ISOCKS_DEFAULT_SOCKS_VERSION;
    reply.atype = ISOCKS_SOCKS5_ADDR_TYPE_IPV4;
    // TODO reply.port = config->port;
    ievent_buffer_event_write(bev, &reply, sizeof(isocks_socks5_reply_t));
    return ISSHE_SUCCESS;
}

isshe_int_t
socks5_bind_cmd_process()
{
    // TODO
    return ISSHE_SUCCESS;
}


isshe_int_t
socks5_request_process(ievent_buffer_event_t *bev,
    isshe_connection_t *conn, isshe_log_t *log, isocks_socks5_info_t *info)
{
    isshe_size_t            len;
    isocks_socks5_request_t request;
    isocks_socks5_reply_t   reply;

    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < sizeof(isocks_socks5_request_t)) {
        isshe_log_debug(log, "waiting for more socks5 request data");
        return ISSHE_SUCCESS;
    }

    ievent_buffer_event_read(bev, &request, sizeof(isocks_socks5_request_t));
    if (!is_valid_socks5_request(&request)) {
        isshe_log_warning(log, "got invalid socks5 request");
        return ISSHE_FAILURE;
    }

    switch (request.cmd) {
        case ISOCKS_SOCKS5_CMD_CONNECT:
            return socks5_connect_cmd_process(bev, &request, conn, log, info);
        case ISOCKS_SOCKS5_CMD_BIND:
            return socks5_bind_cmd_process();
        case ISOCKS_SOCKS5_CMD_UDP_ASSOCIATE:
            break;
        default:
            break;
    }

    return ISSHE_SUCCESS;
}