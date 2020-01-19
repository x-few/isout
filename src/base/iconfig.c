
#include "iconfig.h"

void iconfig_print(iconfig_t *config)
{
    printf(
        "-----------------isout config----------------" ISSHE_LINEFEED
        "config file        : %s" ISSHE_LINEFEED
        "log file           : %s" ISSHE_LINEFEED
        "log level          : %d" ISSHE_LINEFEED
        ,
        config->config_file,
        config->log_file,
        config->log_level);
}

isshe_char_t *
iconfig_log_parse(isshe_json_t *json, isshe_int_t *level)
{
    isshe_json_t *log;
    isshe_json_t *tmp;
    isshe_char_t *filename;

    filename = NULL;
    *level = ISSHE_LOG_NOTICE;
    
    if (!json) {
        return NULL;
    }

    log = isshe_json_get_object(json, "log");
    if (!log) {
        return NULL;
    }

    tmp = isshe_json_get_object(log, "filename");
    if (tmp && tmp->type == ISSHE_JSON_STRING && strlen(tmp->vstring) > 0) {
        //filename = isshe_strdup(tmp->vstring, strlen(tmp->vstring) + 1);
        filename = tmp->vstring;    // 直接指向，不复制了
    }

    tmp = isshe_json_get_object(log, "level");
    if (tmp && tmp->type == ISSHE_JSON_STRING) {
        *level = isshe_log_level_to_number(tmp->vstring);
        if (*level == ISSHE_FAILURE) {
            *level = ISSHE_LOG_NOTICE;
        }
    }

    return filename;
}

isshe_int_t
iconfig_connection_parse(isshe_json_t *json, iconnection_t *conn)
{
    isshe_json_t *tmp;
    isshe_int_t type;

    if (!conn || !json) {
        return ISSHE_FAILURE;
    }

    tmp = isshe_json_get_object(json, "addr");
    if (!tmp || tmp->type != ISSHE_JSON_STRING) {
        return ISSHE_FAILURE;
    }
    conn->addr_str = tmp->vstring;
    // TODO 解析类型
    type = iconn_addr_type_get(conn->addr_str);
    // TODO 解析成sockaddr
    if (iconn_addr_pton(conn->addr_str, type, &conn->addr) == ISSHE_FAILURE) {
        return ISSHE_FAILURE;
    }

    tmp = isshe_json_get_object(json, "port");
    if (!tmp || tmp->type != ISSHE_JSON_NUMBER) {
        return ISSHE_FAILURE;
    }
    conn->port = (isshe_uint16_t)tmp->vint;

    tmp = isshe_json_get_object(json, "protocol");
    if (!tmp || tmp->type != ISSHE_JSON_STRING) {
        return ISSHE_FAILURE;
    }
    conn->protocol_str = tmp->vstring;
    conn->protocol = iconn_protocol_type_get(conn->protocol_str);

    return ISSHE_SUCCESS;
}



void iconfig_parse(iconfig_t *config, const isshe_char_t *filename)
{
    isshe_json_t *json;
    isshe_char_t *buf;

    // read json
    json = isshe_read_json(filename);

    // parse config: log
    config->log_file = iconfig_log_parse(json, &config->log_level);

    // print json
    buf = isshe_json_print(json);
    printf("%s\n", buf);
    isshe_free(buf, NULL);

    // free json
    //isshe_json_delete(json);
    config->config_json = json;
}

iconfig_t *iconfig_new()
{
    iconfig_t *config;

    config = (iconfig_t *)isshe_malloc(sizeof(iconfig_t), NULL);
    if (!config) {
        return NULL;
    }

    isshe_memzero(config, sizeof(iconfig_t));
    return config;
}


void iconfig_free(iconfig_t **pconfig)
{
    iconfig_t *config = *pconfig;
    if (!config) {
        return ;
    }

    isshe_free(config->log_file, NULL);
    isshe_json_delete(config->config_json);
    //isshe_memzero(config, sizeof(iconfig_t));
    isshe_free(config, NULL);
    *pconfig = NULL;
}

