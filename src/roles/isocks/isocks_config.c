

#include "isocks.h"

isshe_int_t
isocks_config_parse(isocks_config_t *config, isshe_json_t *json, isshe_log_t *log)
{
    isshe_json_t *isocks_json;
    isshe_json_t *tmp;

    if (!json) {
        return ISSHE_ERROR;
    }

    isocks_json = isshe_json_object_get(json, ISOCKS_CONFIG_KEY);
    if (!isocks_json) {
        isshe_log_alert(log, "isocks: cannot found isocks config");
        return ISSHE_ERROR;
    }

    // 解析日志级别、日志文件路径
    config->log_file = iconfig_log_parse(isocks_json, &config->log_level);

    // 解析出口/入口的地址、端口、协议
    tmp = isshe_json_object_get(isocks_json, "in");
    config->inarray = iconfig_connection_parse(config->mempool, tmp, &config->nin);
    if (!config->inarray) {
        isshe_log_alert(log, "isocks: invalid inbound config");
        return ISSHE_ERROR;
    }

    tmp = isshe_json_object_get(isocks_json, "out");
    config->outarray = iconfig_connection_parse(config->mempool, tmp, &config->nout);
    if (!config->outarray) {
        isshe_log_alert(log, "isocks: invalid outbound config");
        return ISSHE_ERROR;
    }

    tmp = isshe_json_object_get(isocks_json, "connpool");
    config->connpool_size = ISOCKS_CONNPOOL_DEFAULT_SIZE;
    if (isshe_json_is_number(tmp)) {
        config->connpool_size = (isshe_size_t)(tmp->vnumber);
    }

    return ISSHE_OK;
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
        "- log level:file       : %s:%s",
        isshe_log_level_to_string(config->log_level), config->log_file);

    for (i = 0; i < config->nin; i++) {
        isshe_log_info(log,
            "- in addr              : %s:%d:%s",
            config->inarray[i].addr->addr,
            config->inarray[i].addr->port,
            config->inarray[i].protocol_text);
    }

    for (i = 0; i < config->nout; i++) {
        isshe_log_info(log,
            "- out addr             : %s:%d:%s",
            config->outarray[i].addr->addr,
            config->outarray[i].addr->port,
            config->outarray[i].protocol_text);
    }
    isshe_log_info(log,
        "- connection pool size : %d", config->connpool_size);
    isshe_log_info(log,
        "=====================================================");
}
