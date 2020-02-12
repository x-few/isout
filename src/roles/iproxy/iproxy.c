
#include "isout.h"

void iproxy_start(void *ctx)
{
    iconfig_t               *all_config = (iconfig_t *)ctx;
    isshe_log_t             *log = all_config->log;              // 先使用master的log，自己的起来后，再使用自己的。
    isshe_mempool_t         *mempool;
    iproxy_config_t         *iproxy_config;
    isshe_int_t             i;
    ievent_listener_t       *listener;

    isshe_log_notice(log, "iproxy_start: pid = %d", getpid());

    //iproxy_signal_init(log);

    // 初始化内存池
    mempool = isshe_mempool_create(IPROXY_DEFAULT_MEMPOOL_SIZE, log);
    if (!mempool) {
        isshe_log_alert(log, "iproxy: create memory pool failed");
        goto iproxy_error;
    }

    // 配置解析
    iproxy_config = isshe_mpalloc(mempool, sizeof(iproxy_config_t));
    if (!iproxy_config) {
        isshe_log_alert(log, "iproxy: malloc iproxy config failed");
        goto iproxy_error;
    }

    iproxy_config->mempool = mempool;
    if (iproxy_config_parse(iproxy_config, all_config->config_json, log) == ISSHE_FAILURE) {
        isshe_log_alert(log, "iproxy: config parse failed");
        goto iproxy_error;
    }

    iproxy_config_print(iproxy_config, log);

    // 初始化log
    iproxy_config->log = isshe_log_create(
        iproxy_config->log_level, iproxy_config->log_file);
    if (!iproxy_config->log) {
        isshe_log_alert(log, "create iproxy log failed");
        goto iproxy_error;
    }

    if (iproxy_config->log_file) {
        isshe_log_notice(log, "iproxy log file change to %s",
            iproxy_config->log_file);
    }

    // update mempool log
    iproxy_config->mempool->log = iproxy_config->log;

    // 初始化连接池
    iproxy_config->connpool = isshe_connpool_create(
        iproxy_config->connpool_size,
        iproxy_config->mempool, iproxy_config->log);

    // TODO 屏蔽信号（需要吗）
    // TODO 设置进程标题
    isshe_process_title_set("isout: iproxy");

    iproxy_config->event = ievent_create(
        iproxy_config->mempool, iproxy_config->log);
    if (!iproxy_config->event) {
        isshe_log_alert(iproxy_config->log, "create event failed");
        goto iproxy_error;
    }

    for (i = 0; i < iproxy_config->nin; i++) {
        isshe_log_notice(iproxy_config->log,
            "listening: %s:%d",
            iproxy_config->inarray[i].addr->addr,
            iproxy_config->inarray[i].addr->port);
        isshe_debug_print_addr(
            (struct sockaddr *)iproxy_config->inarray[i].addr->sockaddr,
            iproxy_config->log);        // DEBUG!

        listener = ievent_listener_create(iproxy_config->event,
                        iproxy_event_accept_cb, (void *)iproxy_config,
                        iproxy_config->inarray[i].addr->sockaddr,
                        iproxy_config->inarray[i].addr->socklen);
        if (!listener) {
            isshe_log_alert(iproxy_config->log, "listener create failed");
            goto iproxy_error;
        }

        iproxy_config->inarray[i].data = (void *)listener;
    }

    ievent_dispatch(iproxy_config->event);
 
 iproxy_error:
    if (iproxy_config->connpool) {
        isshe_connpool_destroy(iproxy_config->connpool);
    }

    if (iproxy_config->mempool) {
        isshe_mempool_destroy(iproxy_config->mempool);
    }

    if (iproxy_config->log && iproxy_config->log != log) {
        isshe_log_destroy(iproxy_config->log);
    }

    // never return!
    exit(0);
}