

#include "isocks_config.h"

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
    if (iconfig_connection_parse(tmp, &config->in) == ISSHE_FAILURE) {
        isshe_log_alert(log, "isocks: invalid inbound config");
        return ISSHE_FAILURE;
    }

    tmp = isshe_json_get_object(isocks_json, "out");
    if (iconfig_connection_parse(tmp, &config->out) == ISSHE_FAILURE) {
        isshe_log_alert(log, "isocks: invalid outbound config");
        return ISSHE_FAILURE;
    }

    return ISSHE_SUCCESS;
}

void
isocks_config_print(isocks_config_t *config, isshe_log_t *log)
{
    if (log) {
        isshe_log_info(log,
            "==================== isocks config =================="
            "- log level        : %s" ISSHE_LINEFEED
            "- log file         : %s" ISSHE_LINEFEED
            "- in addr          : %s" ISSHE_LINEFEED
            "- in port          : %d" ISSHE_LINEFEED
            "- in protocol      : %s" ISSHE_LINEFEED
            "- out addr         : %s" ISSHE_LINEFEED
            "- out port         : %d" ISSHE_LINEFEED
            "- out protocol     : %s" ISSHE_LINEFEED
            "=====================================================",
            config->log_level, config->log_filename, 
            config->in.addr_str, config->in.port, 
            config->in.protocol_str, 
            config->out.addr_str, config->out.port, 
            config->out.protocol_str);
    } else {
        printf(
            "==================== isocks config =================="
            "- log level        : %s" ISSHE_LINEFEED
            "- log file         : %s" ISSHE_LINEFEED
            "- in addr          : %s" ISSHE_LINEFEED
            "- in port          : %d" ISSHE_LINEFEED
            "- in protocol      : %s" ISSHE_LINEFEED
            "- out addr         : %s" ISSHE_LINEFEED
            "- out port         : %d" ISSHE_LINEFEED
            "- out protocol     : %s" ISSHE_LINEFEED
            "=====================================================",
            isshe_log_level_to_string(config->log_level),
            config->log_filename, 
            config->in.addr_str, config->in.port, 
            config->in.protocol_str, 
            config->out.addr_str, config->out.port, 
            config->out.protocol_str);
    }
}
