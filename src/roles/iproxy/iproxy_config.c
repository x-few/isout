

#include "iproxy.h"

isshe_int_t
iproxy_config_parse(iproxy_config_t *config, isshe_json_t *json, isshe_log_t *log)
{
    isshe_json_t *iproxy_json;
    isshe_json_t *tmp;

    if (!json) {
        return ISSHE_FAILURE;
    }

    iproxy_json = isshe_json_get_object(json, IPROXY_CONFIG_KEY);
    if (!iproxy_json) {
        isshe_log_alert(log, "iproxy: cannot found iproxy config");
        return ISSHE_FAILURE;
    }

    // 解析日志级别、日志文件路径
    config->log_file = iconfig_log_parse(iproxy_json, &config->log_level);

    // 解析出口/入口的地址、端口、协议
    tmp = isshe_json_get_object(iproxy_json, "in");
    config->inarray = iconfig_connection_parse(config->mempool, tmp, &config->nin);
    if (!config->inarray) {
        isshe_log_alert(log, "iproxy: invalid inbound config");
        return ISSHE_FAILURE;
    }

    tmp = isshe_json_get_object(iproxy_json, "connpool");
    config->connpool_size = IPROXY_CONNPOOL_DEFAULT_SIZE;
    if (isshe_json_is_number(tmp)) {
        config->connpool_size = tmp->vint;
    }

    return ISSHE_SUCCESS;
}

void
iproxy_config_print(iproxy_config_t *config, isshe_log_t *log)
{
    isshe_int_t i;

    if (!config || !log) {
        return ;
    }

    isshe_log_info(log,
        "==================== iproxy config ==================");
    isshe_log_info(log,
        "- log level:file       : %d:%s",
        config->log_level, config->log_file);

    for (i = 0; i < config->nin; i++) {
        isshe_log_info(log,
            "- in addr              : %s:%d:%s",
            config->inarray[i].addr_text,
            config->inarray[i].port,
            config->inarray[i].protocol_text);
    }

    isshe_log_info(log,
        "- connection pool size : %d", config->connpool_size);
    isshe_log_info(log,
        "=====================================================");
}
