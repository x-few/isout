
#include "isocks.h"

isshe_int_t
isocks_socks5_selction_message_process(
    ievent_buffer_event_t *bev, isshe_log_t *log)
{
    isshe_size_t                len;
    socks5_selection_request_t  request;
    socks5_selection_reply_t    reply;

    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < sizeof(socks5_selection_request_t)) {
        // 等待更多数据
        isshe_log_debug(log,
            "waiting for more socks5 selection request data: expect %d, got %d",
            sizeof(socks5_selection_request_t), len);
        return ISSHE_AGAIN;
    }

    ievent_buffer_event_read(bev, &request, sizeof(socks5_selection_request_t));
    if (!is_valid_socks5_selection_request(&request)) {
        isshe_log_warning(log, "got invalid socks5 request");
        return ISSHE_ERROR;
    }

    isshe_memzero(&reply, sizeof(socks5_selection_reply_t));
    reply.version = SOCKS_PROTOCOL_V5;
    ievent_buffer_event_write(bev, &reply, sizeof(socks5_selection_reply_t));
    return ISSHE_OK;
}


isshe_int_t
isocks_socks5_connect_cmd_process(
    ievent_buffer_event_t *bev,
    socks5_request_t *request,
    isshe_connection_t *conn,
    isshe_log_t *log,
    isshe_address_t *addr)
{
    isshe_mempool_t     *mempool = conn->mempool;
    socks5_reply_t      reply;
    isshe_size_t        len;

    // request cmd
    switch (request->atype)
    {
        case SOCKS5_ADDR_TYPE_DOMAIN:
            ievent_buffer_event_read(bev, &addr->addr_len, sizeof(addr->addr_len));
            break;
        case SOCKS5_ADDR_TYPE_IPV4:
            addr->addr_len = ISSHE_IPV4_ADDR_LEN;
            break;
        case SOCKS5_ADDR_TYPE_IPV6:
            addr->addr_len = ISSHE_IPV6_ADDR_LEN;
            break;
        default:
            isshe_log_warning(log, "unsupported sock5 addr type");
            return ISSHE_ERROR;
    }

    addr->addr_type = request->atype;
    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < addr->addr_len + sizeof(addr->port)) {
        isshe_log_warning(log, "expect len %d, got len %d",
            addr->addr_len + sizeof(addr->port), len);
        return ISSHE_ERROR;
    }
    addr->addr = (isshe_char_t *)isshe_mpalloc(mempool, addr->addr_len);
    if (!addr->addr) {
        isshe_log_alert(log, "mpalloc socks5 addr_text failed");
        return ISSHE_ERROR;
    }

    ievent_buffer_event_read(bev, addr->addr, addr->addr_len);
    ievent_buffer_event_read(bev, &addr->port, sizeof(addr->port));
    // TODO IPv4 ntohs
    addr->port = ntohs(addr->port);

    // reply
    isshe_memzero(&reply, sizeof(socks5_reply_t));
    reply.version = request->version;
    reply.atype = SOCKS5_ADDR_TYPE_IPV4;
    // TODO reply.port = config->port;
    ievent_buffer_event_write(bev, &reply, sizeof(socks5_reply_t));
    return ISSHE_OK;
}

isshe_int_t
isocks_socks5_bind_cmd_process()
{
    // TODO
    return ISSHE_OK;
}


isshe_int_t
isocks_socks5_request_process(
    ievent_buffer_event_t *bev,
    isshe_connection_t *conn,
    isshe_log_t *log,
    isshe_address_t *info)
{
    isshe_size_t     len;
    socks5_request_t request;
    socks5_reply_t   reply;

    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < sizeof(socks5_request_t)) {
        isshe_log_debug(log, "waiting for more socks5 request data");
        return ISSHE_AGAIN;
    }

    ievent_buffer_event_read(bev, &request, sizeof(socks5_request_t));
    if (!is_valid_socks5_request(&request)) {
        isshe_log_warning(log, "got invalid socks5 request");
        return ISSHE_ERROR;
    }

    if (!is_support_socks5_addr_type(request.atype)) {
        isshe_log_warning(log,
            "no support socks5 request addr type(%d)",
            request.atype);
        return ISSHE_ERROR;
    }

    switch (request.cmd) {
        case SOCKS5_CMD_CONNECT:
            return isocks_socks5_connect_cmd_process(
                bev, &request, conn, log, info);
        case SOCKS5_CMD_BIND:
            return isocks_socks5_bind_cmd_process();
        case SOCKS5_CMD_UDP_ASSOCIATE:
            break;
        default:
            break;
    }

    return ISSHE_ERROR;
}


isshe_int_t
isocks_socks4_connect_cmd_process(
    ievent_buffer_event_t *bev,
    socks4_request_t *request,
    isshe_connection_t *conn,
    isshe_log_t *log,
    isshe_address_t *addr)
{
    isshe_mempool_t     *mempool = conn->mempool;
    socks4_reply_t      reply;
    isshe_size_t        len;

    addr->addr = (isshe_char_t *)isshe_mpalloc(mempool, addr->addr_len);
    if (!addr->addr) {
        isshe_log_alert(log, "mpalloc socks4 addr failed");
        return ISSHE_ERROR;
    }
    addr->addr_len = ISSHE_IPV4_ADDR_LEN;
    addr->addr_type = ISSHE_ADDR_TYPE_IPV4;
    isshe_memcpy(addr->addr, request->daddr, addr->addr_len);
    addr->port = ntohs(request->dport);

    isshe_memzero(&reply, sizeof(reply));
    reply.cmd = SOCKS4_REQUEST_GRANTED;
    ievent_buffer_event_write(bev, &reply, sizeof(reply));

    return ISSHE_OK;
}

isshe_int_t
isocks_socks4_bind_cmd_process()
{
    // TODO
    return ISSHE_OK;
}

isshe_int_t
isocks_socks4_request_process(
    ievent_buffer_event_t *bev,
    isshe_connection_t *conn,
    isshe_log_t *log,
    isshe_address_t *info)
{
    isshe_size_t     len;
    socks4_request_t request;
    socks4_reply_t   reply;

    len = ievent_buffer_get_length(ievent_buffer_event_get_input(bev));
    if (len < sizeof(socks4_request_t)) {
        isshe_log_debug(log, "waiting for more socks4 request data");
        return ISSHE_AGAIN;
    }

    ievent_buffer_event_read(bev, &request, sizeof(socks4_request_t));
    if (!is_valid_socks4_request(&request)) {
        isshe_log_warning(log, "got invalid socks5 request");
        return ISSHE_ERROR;
    }

    switch (request.cmd) {
        case SOCKS4_CMD_CONNECT:
            return isocks_socks4_connect_cmd_process(
                bev, &request, conn, log, info);
        case SOCKS4_CMD_BIND:
            return isocks_socks4_bind_cmd_process();
        default:
            break;
    }

    return ISSHE_ERROR;
}