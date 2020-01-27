

#include "isocks.h"

isshe_int_t
isocks_config_parse(isocks_config_t *config, isshe_json_t *json, isshe_log_t *log)
{
    isshe_json_t *isocks_json;
    isshe_json_t *tmp;

    if (!json) {
        return ISSHE_FAILURE;
    }

    isocks_json = isshe_json_get_object(json, ISOCKS_CONFIG_KEY);
    if (!isocks_json) {
        isshe_log_alert(log, "isocks: cannot found isocks config");
        return ISSHE_FAILURE;
    }

    // 解析日志级别、日志文件路径
    config->log_filename = iconfig_log_parse(isocks_json, &config->log_level);

    // 解析出口/入口的地址、端口、协议
    tmp = isshe_json_get_object(isocks_json, "in");
    config->inarray = iconfig_connection_parse(config->mempool, tmp, &config->nin);
    if (!config->inarray) {
        isshe_log_alert(log, "isocks: invalid inbound config");
        return ISSHE_FAILURE;
    }

    tmp = isshe_json_get_object(isocks_json, "out");
    config->outarray = iconfig_connection_parse(config->mempool, tmp, &config->nout);
    if (!config->outarray) {
        isshe_log_alert(log, "isocks: invalid outbound config");
        return ISSHE_FAILURE;
    }

    tmp = isshe_json_get_object(isocks_json, "connpool");
    config->connpool_size = ISOCKS_CONNPOOL_DEFAULT_SIZE;
    if (isshe_json_is_number(tmp)) {
        config->connpool_size = tmp->vint;
    }

    return ISSHE_SUCCESS;
}

void
isocks_config_print(isocks_config_t *config, isshe_log_t *log)
{
    isshe_int_t i;

    if (!config || !log) {
        return ;
    }

    isshe_log_info(log,
        "==================== isocks config ==================");
    isshe_log_info(log,
        "- log level:file       : %d:%s",
        config->log_level, config->log_filename);

    for (i = 0; i < config->nin; i++) {
        isshe_log_info(log,
            "- in addr              : %s:%d:%s",
            config->inarray[i].addr_text,
            config->inarray[i].port,
            config->inarray[i].protocol_text);
    }

    for (i = 0; i < config->nout; i++) {
        isshe_log_info(log,
            "- out addr             : %s:%d:%s",
            config->outarray[i].addr_text,
            config->outarray[i].port,
            config->outarray[i].protocol_text);
    }
    isshe_log_info(log,
        "- connection pool size : %d", config->connpool_size);
    isshe_log_info(log,
        "=====================================================");
}
