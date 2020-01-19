
#include "isocks.h"

void isocks_start(void *ctx)
{
    iconfig_t *all_config = (iconfig_t *)ctx;
    isshe_log_t *log = all_config->log;              // 先使用master的log，自己的起来后，再使用自己的。
    isshe_mempool_t *pool;
    isocks_config_t *isocks_config;

    // 初始化内存池
    pool = isshe_mempool_create(ISOCKS_DEFAULT_POOL_SIZE, (isshe_log_t *)log);
    if (!pool) {
        isshe_log_alert(log, "isocks: create memory pool failed");
        exit(0);
    }
    
    // 配置解析
    isocks_config = isshe_mpalloc(pool, sizeof(isocks_config_t));
    if (!isocks_config) {
        isshe_log_alert(log, "isocks: malloc isocks config failed");
        exit(0);
    }
    if (isocks_config_parse(isocks_config, all_config->config_json, log) == ISSHE_FAILURE) {
        isshe_log_alert(log, "isocks: config parse failed");
        exit(0);
    }

    // 初始化log

    // 初始化连接池

    // TODO 屏蔽信号（需要吗）
    // TODO 设置进程标题
    isshe_process_title_set("isout: isocks");
    sleep(30);

    // TODO...
    isshe_log_debug(all_config->log, "---in isocks_start: pid = %d", getpid());
    
    // never return!
    exit(0);
}