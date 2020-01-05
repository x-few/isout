

#include "isshe_file.h"
#include "isshe_json.h"
#include "isshe_unistd.h"

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


void iconfig_parse(iconfig_t *config, const isshe_char_t *filename)
{
    isshe_json_t *json;
    isshe_char_t *buf;

    // read json
    json = isshe_read_json(filename);

    // parse config: log
    isshe_json_t *log = isshe_json_get_object(json, "log");
    isshe_json_t *tmp = isshe_json_get_object(log, "filename");
    if (tmp && tmp->type == ISSHE_JSON_STRING && strlen(tmp->vstring) > 0) {
        isshe_string_mirror(&config->log_file, tmp->vstring, strlen(tmp->vstring));
    }
    tmp = isshe_json_get_object(log, "level");
    if (tmp && tmp->type == ISSHE_JSON_STRING) {
        config->log_level = isshe_log_level_to_number(tmp->vstring);
        if (config->log_level == ISSHE_FAILURE) {
            config->log_level = ISSHE_LOG_NOTICE;
        }
    }

    // print json
    buf = isshe_json_print(json);
    printf("%s\n", buf);
    isshe_free(buf);

    // free json
    //isshe_json_delete(json);
    config->config_json = json;
}

iconfig_t *iconfig_new()
{
    iconfig_t *config;

    config = (iconfig_t *)isshe_malloc(sizeof(iconfig_t));
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

    ilog_uninit(config->log);
    isshe_free(config->log_file);
    isshe_json_delete(config->config_json);
    //isshe_memzero(config, sizeof(iconfig_t));
    isshe_free(config);
    *pconfig = NULL;
}

