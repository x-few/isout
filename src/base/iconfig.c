
#include "isout.h"

void iconfig_print(iconfig_t *config)
{
    printf(
        "-----------------isout config----------------" ISSHE_LINEFEED
        "config file        : %s" ISSHE_LINEFEED
        "log file           : %s" ISSHE_LINEFEED
        "log level          : %d" ISSHE_LINEFEED
        "-----------------isout config----------------" ISSHE_LINEFEED
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

    log = isshe_json_object_get(json, "log");
    if (!log) {
        return NULL;
    }

    tmp = isshe_json_object_get(log, "filename");
    if (isshe_json_is_string(tmp)) {
        filename = tmp->vstring;    // 直接指向，不复制了
    }

    tmp = isshe_json_object_get(log, "level");
    if (tmp && tmp->type == ISSHE_JSON_STRING) {
        *level = isshe_log_level_to_number(tmp->vstring);
        if (*level == ISSHE_ERROR) {
            *level = ISSHE_LOG_NOTICE;
        }
    }

    return filename;
}

isshe_connection_t *
iconfig_connection_parse(isshe_mempool_t *mempool, 
                        isshe_json_t *json_array,
                        isshe_int_t *res_nconn)
{
    isshe_json_t        *tmp_json;
    isshe_json_t        *conn_json;
    isshe_connection_t  *conn_array;
    isshe_connection_t  *conn;
    isshe_int_t         n, i;
    struct sockaddr_in  *tmpaddr;
    isshe_char_t        *addr_text;
    isshe_uint8_t       addr_len;
    isshe_uint8_t       addr_type;
    isshe_log_t         *log = mempool->log;

    if (!isshe_json_is_array(json_array)) {
        isshe_log_alert(log, "parameter error: json is not array");
        return NULL;
    }

    n = isshe_json_array_size(json_array);

    conn_array = isshe_mpalloc(mempool, n * sizeof(isshe_connection_t));
    if (!conn_array) {
        isshe_log_alert(log, "malloc connection array failed");
        return NULL;
    }

    for (i = 0; i < n; i++) {
        conn_json = isshe_json_array_item_get(json_array, i);
        if (!conn_json) {
            isshe_log_alert(log, "get array item failed: index = %d", i);
            return NULL;
        }

        conn = &conn_array[i];
        

        tmp_json = isshe_json_object_get(conn_json, "addr");
        if (!isshe_json_is_string(tmp_json)) {
            isshe_log_alert(log, "config 'addr' is not string");
            return NULL;
        }
        addr_text = tmp_json->vstring;
        addr_len = strlen(addr_text) + 1;
        addr_type = isshe_address_type_get(addr_text, addr_len);
        conn->addr = isshe_address_create(addr_text,
            addr_len, addr_type, mempool, log);
        if (!conn->addr) {
            isshe_log_alert(log,
                "create address failed: addr = (%d)%s",
                addr_len, addr_text);
            return NULL;
        }

        if (!isshe_address_sockaddr_create(conn->addr, mempool, log)) {
            isshe_log_alert(log,
                "create sockaddr failed: addr = (%d)%s",
                addr_len, addr_text);
            return NULL;
        }

        tmp_json = isshe_json_object_get(conn_json, "port");
        if (!isshe_json_is_number(tmp_json)) {
            isshe_log_alert(log, "config 'port' is not number");
            return NULL;
        }

        isshe_address_port_set(conn->addr,
            (isshe_uint16_t)(tmp_json->vnumber));

        tmp_json = isshe_json_object_get(conn_json, "protocol");
        if (!isshe_json_is_string(tmp_json)) {
            isshe_log_alert(log, "config 'protocol' is not string");
            return NULL;
        }
        conn->protocol_text = tmp_json->vstring;
        conn->protocol = iprotocol_type_get(conn->protocol_text);
    }

    *res_nconn = n;

    return conn_array;
}



void iconfig_parse(iconfig_t *config,
    const isshe_char_t *filename,
    isshe_mempool_t *mempool)
{
    isshe_json_t *json;
    //isshe_char_t *buf;

    // read json
    json = isshe_json_file_parse(filename, mempool);

    // parse config: log
    config->log_file = iconfig_log_parse(json, &config->log_level);

    // print json
    //buf = 
    isshe_json_print(json, NULL);
    //printf("%s\n", buf);
    //isshe_free(buf);

    // free json
    //isshe_json_delete(json);
    config->config_json = json;
}

iconfig_t *iconfig_create()
{
    iconfig_t *config;

    config = (iconfig_t *)isshe_malloc(sizeof(iconfig_t));
    if (!config) {
        return NULL;
    }

    isshe_memzero(config, sizeof(iconfig_t));
    return config;
}


void iconfig_destroy(iconfig_t *config)
{
    if (!config) {
        return ;
    }

    // TODO 完善这里：改用内存池；释放log。
    isshe_free(config->log_file);
    isshe_json_delete(config->config_json, config->mempool);
    //isshe_memzero(config, sizeof(iconfig_t));

    if (config->mempool) {
        isshe_mempool_destroy(config->mempool);
    }

    isshe_free(config);
}

