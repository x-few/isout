

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
        ,
        config->config_file,
        config->log_file);
}


void iconfig_parse(iconfig_t *config, const isshe_char_t *filename)
{
    isshe_json_t *json;
    isshe_char_t *buf;

    // read json
    json = isshe_read_json(filename);

    // parse config
    isshe_json_t *log = isshe_json_get_object(json, "log");
    isshe_json_t *tmp = isshe_json_get_object(log, "filename");
    if (tmp && tmp->type == ISSHE_JSON_STRING) {
        isshe_string_mirror(&config->log_file, tmp->vstring, strlen(tmp->vstring));
    }

    // print json
    buf = isshe_json_print(json);
    printf("%s\n", buf);
    isshe_free(buf);

    // free json
    isshe_json_delete(json);
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

void iconfig_free(iconfig_t *config)
{
    if (!config) {
        return ;
    }

    isshe_free(config->log_file);
    isshe_free(config);
}

