
#include "isocks.h"

void isocks_start(void *ctx)
{
    iconfig_t               *all_config = (iconfig_t *)ctx;
    isshe_log_t             *log = all_config->log;              // 先使用master的log，自己的起来后，再使用自己的。
    isshe_mempool_t         *mempool;
    isocks_config_t         *isocks_config;
    isshe_int_t             i;
    ievent_listener_t       *listener;

    isshe_log_notice(log, "isocks_start: pid = %d", getpid());

    // 初始化内存池
    mempool = isshe_mempool_create(ISOCKS_DEFAULT_MEMPOOL_SIZE, log);
    if (!mempool) {
        isshe_log_alert(log, "isocks: create memory pool failed");
        goto isocks_error;
    }

    // 配置解析
    isocks_config = isshe_mpalloc(mempool, sizeof(isocks_config_t));
    if (!isocks_config) {
        isshe_log_alert(log, "isocks: malloc isocks config failed");
        goto isocks_error;
    }

    isocks_config->mempool = mempool;
    if (isocks_config_parse(isocks_config, all_config->config_json, log) == ISSHE_FAILURE) {
        isshe_log_alert(log, "isocks: config parse failed");
        goto isocks_error;
    }

    isocks_config_print(isocks_config, log);
    isocks_config->log = isshe_log_create(
        isocks_config->log_level, isocks_config->log_file);
    if (!isocks_config->log) {
        isshe_log_alert(log, "create isocks log failed");
        goto isocks_error;
    }
    // 初始化log
    if (isocks_config->log_file) {
        isshe_log_notice(log, "isocks log file change to %s",
            isocks_config->log_file);
    }

    // update mempool log
    isocks_config->mempool->log = isocks_config->log;

    // 初始化连接池
    isocks_config->connpool = isshe_connpool_create(
        isocks_config->connpool_size,
        isocks_config->mempool, isocks_config->log);

    // TODO 屏蔽信号（需要吗）
    // TODO 设置进程标题
    isshe_process_title_set("isout: isocks");

    isocks_config->event = ievent_create(
        isocks_config->mempool, isocks_config->log);
    if (!isocks_config->event) {
        isshe_log_alert(isocks_config->log, "create event failed");
        goto isocks_error;
    }

    for (i = 0; i < isocks_config->nin; i++) {
        isshe_log_notice(isocks_config->log,
            "listening: %s:%d",
            isocks_config->inarray[i].addr->addr,
            isocks_config->inarray[i].addr->port);
        isshe_debug_print_addr(
            (isshe_sa_t *)isocks_config->inarray[i].addr->sockaddr,
            isocks_config->log);        // DEBUG!

        listener = ievent_listener_create(isocks_config->event,
                        isocks_event_accept_cb, (void *)isocks_config,
                        isocks_config->inarray[i].addr->sockaddr,
                        isocks_config->inarray[i].addr->socklen);
        if (!listener) {
            isshe_log_alert(isocks_config->log, "listener create failed");
            goto isocks_error;
        }

        isocks_config->inarray[i].data = (void *)listener;
    }

    ievent_dispatch(isocks_config->event);
 
 isocks_error:
    if (isocks_config->connpool) {
        isshe_connpool_destroy(isocks_config->connpool);
    }

    if (isocks_config->mempool) {
        isshe_mempool_destroy(isocks_config->mempool);
    }

    if (isocks_config->log && isocks_config->log != log) {
        isshe_log_destroy(isocks_config->log);
    }

    // never return!
    exit(0);
}