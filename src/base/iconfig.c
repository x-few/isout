
#include "isout.h"

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
    isshe_char_t *filename = NULL;

    *level = ISSHE_LOG_NOTICE;

    if (!json) {
        return NULL;
    }

    log = isshe_json_get_object(json, "log");
    if (!log) {
        return NULL;
    }

    tmp = isshe_json_get_object(log, "filename");
    if (isshe_json_is_string(tmp)) {
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

isshe_connection_t *
iconfig_connection_parse(isshe_mempool_t *pool, 
                        isshe_json_t *json_array,
                        isshe_int_t *res_nconn)
{
    isshe_json_t        *tmp_json;
    isshe_json_t        *conn_json;
    isshe_connection_t  *conn_array;
    isshe_connection_t  *conn;
    isshe_int_t         type;
    isshe_int_t         n, i;
    struct sockaddr_in  *tmpaddr;

    if (!isshe_json_is_array(json_array)) {
        isshe_log_alert(pool->log, "parameter error: json is not array");
        return NULL;
    }

    n = isshe_json_get_array_size(json_array);

    conn_array = isshe_mpalloc(pool, n * sizeof(isshe_connection_t));
    if (!conn_array) {
        isshe_log_alert(pool->log, "malloc connection array failed");
        return NULL;
    }

    for (i = 0; i < n; i++) {
        conn_json = isshe_json_get_array(json_array, i);
        if (!conn_json) {
            isshe_log_alert(pool->log, "get array item failed: index = %d", i);
            return NULL;
        }

        conn = &conn_array[i];

        tmp_json = isshe_json_get_object(conn_json, "addr");
        if (!isshe_json_is_string(tmp_json)) {
            isshe_log_alert(pool->log, "config 'addr' is not string");
            return NULL;
        }
        conn->addr_text = tmp_json->vstring;
        // TODO 解析类型
        type = isshe_conn_addr_type_get(conn->addr_text);
        // TODO 解析成sockaddr
        if (isshe_conn_addr_pton(conn->addr_text,
        type, &conn->sockaddr, &conn->socklen) == ISSHE_FAILURE) {
            isshe_log_alert(pool->log, "convert addr string to socksaddr failed");
            return NULL;
        }

        tmp_json = isshe_json_get_object(conn_json, "port");
        if (!isshe_json_is_number(tmp_json)) {
            isshe_log_alert(pool->log, "config 'port' is not number");
            return NULL;
        }
        conn->port = (isshe_uint16_t)(tmp_json->vint);
        tmpaddr = (struct sockaddr_in *)&conn->sockaddr;
        tmpaddr->sin_port = htons(conn->port);

        tmp_json = isshe_json_get_object(conn_json, "protocol");
        if (!isshe_json_is_string(tmp_json)) {
            isshe_log_alert(pool->log, "config 'protocol' is not string");
            return NULL;
        }
        conn->protocol_text = tmp_json->vstring;
        conn->protocol = iprotocol_type_get(conn->protocol_text);
    }

    *res_nconn = n;

    return conn_array;
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

