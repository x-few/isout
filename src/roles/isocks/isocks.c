
#include "isout.h"
ß
void isocks_start(void *ctx)
{
    iconfig_t           *all_config = (iconfig_t *)ctx;
    isshe_log_t         *log = all_config->log;              // 先使用master的log，自己的起来后，再使用自己的。
    isshe_mempool_t     *mempool;
    isocks_config_t     *isocks_config;

    // 初始化内存池
    mempool = isshe_mempool_create(ISOCKS_DEFAULT_POOL_SIZE, log);
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

    // 初始化log
    if (isocks_config->log_filename) {
        isocks_config->log = isshe_log_create(
            isocks_config->log_filename, isocks_config->log_level);
        isshe_log_notice(log, "isocks log file change to %s", isocks_config->log);
    } else {
        isocks_config->log = log;
    }

    // 初始化连接池
    // isshe_connpool_create(mempool, )

    // TODO 屏蔽信号（需要吗）
    // TODO 设置进程标题
    isshe_process_title_set("isout: isocks");
    sleep(30);

    // TODO...
    isshe_log_debug(all_config->log, "---in isocks_start: pid = %d", getpid());
 
 isocks_error:
    if (mempool) {
        isshe_mempool_destroy(mempool);
    }

    // never return!
    exit(0);
}