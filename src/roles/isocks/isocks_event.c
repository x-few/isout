#include "isout.h"

void
isocks_event_accept_cb(ievent_conn_listener_t *listener, 
    isshe_socket_t fd, struct sockaddr *sockaddr,
    int socklen, void *data)
{
    isocks_config_t     *config;
    isshe_connection_t  *connection = NULL;
    isshe_mempool_t     *mempool = NULL;
    isocks_session_t    *session;

    config = (isocks_config_t *)data;
    isshe_debug_print_addr(sockaddr, config->log);  // DEBUG

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
    session->inevb = ievent_buffer_socket_create(config->event, fd);
    session->outevb = ievent_buffer_socket_create(config->event, ISSHE_INVALID_FILE);

    // 连接下一跳（出口）
    //if (bufferevent_socket_connect(outbev,
	//	(struct sockaddr*)addr, sizeof(struct sockaddr_in)) < 0) {

    // 设置入口回调，读取数据
    // 设置出口回调
    return;

isocks_event_accept_error:
    if (connection) {
        isshe_connection_free(config->connpool, connection);
    }

    // TODO 怎么直接关闭连接？
    ievent_connection_close(fd);
}