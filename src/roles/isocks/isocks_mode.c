/*
 * 设置模式：自动代理或全局代理。
 */

// TODO 待优化

#include "isocks.h"

#if defined ISSHE_APPLE
//"networksetup -setautoproxyurl %s %s"; MacOS无法使用像file://这样的url进行代理文件设置。
static isshe_char_t *auto_proxy_url_fmt = "networksetup -setsocksfirewallproxy %s 127.0.0.1 1081 %s";
//"networksetup -setautoproxystate %s %s";
static isshe_char_t *auto_proxy_mode_fmt = "networksetup -setsocksfirewallproxystate %s %s";
static isshe_char_t *on = "on";
static isshe_char_t *off = "off";
#elif defined ISSHE_LINUX
static isshe_char_t *auto_proxy_url_fmt = "gsettings set org.gnome.system.proxy autoconfig-url %s '%s'";
static isshe_char_t *auto_proxy_mode_fmt = "gsettings set org.gnome.system.proxy mode %s %s";
static isshe_char_t *on = "auto";
static isshe_char_t *off = "none";
#else
// TODO

#endif

isshe_int_t
isocks_auto_proxy_url_set(isshe_char_t *network_service, isshe_char_t *url)
{
    isshe_char_t    cmd[ISOUT_DEFAULT_COMMAND_MAX];
    isshe_int_t     rc;

    isshe_memzero(cmd, ISOUT_DEFAULT_COMMAND_MAX);
    snprintf(cmd, ISOUT_DEFAULT_COMMAND_MAX, auto_proxy_url_fmt, network_service, url);

    if (system(cmd) != 0) {
        return ISSHE_ERROR;
    }

    return ISSHE_OK;
}


isshe_int_t
isocks_auto_proxy_on(isshe_char_t *network_service)
{
    isshe_char_t cmd[ISOUT_DEFAULT_COMMAND_MAX];

    isshe_memzero(cmd, ISOUT_DEFAULT_COMMAND_MAX);
    snprintf(cmd, ISOUT_DEFAULT_COMMAND_MAX, auto_proxy_mode_fmt, network_service, on);

    if (system(cmd) != 0) {
        return ISSHE_ERROR;
    }

    return ISSHE_OK;
}

isshe_int_t
isocks_auto_proxy_off(isshe_char_t *network_service)
{
    isshe_char_t cmd[ISOUT_DEFAULT_COMMAND_MAX];

    isshe_memzero(cmd, ISOUT_DEFAULT_COMMAND_MAX);
    snprintf(cmd, ISOUT_DEFAULT_COMMAND_MAX, auto_proxy_mode_fmt, network_service, off);

    if (system(cmd) != 0) {
        return ISSHE_ERROR;
    }

    return ISSHE_OK;
}

isshe_int_t
isocks_pac_file_generate(isshe_char_t *filename, isshe_log_t *log)
{
    isshe_fd_t  fd;
    isshe_char_t *default_pac_content =
        "var proxy = \"SOCKS5 127.0.0.1:1081; SOCKS 127.0.0.1:1081; DIRECT;\";\n"
        "\n"
        "function FindProxyForURL(url, host) {\n"
        "    return proxy;\n"
        "}";

    fd = isshe_open(filename, ISSHE_FILE_CRWR, ISSHE_FILE_DEFAULT_ACCESS);
    if (fd == ISSHE_INVALID_FD) {
        isshe_log_debug_errno(log, errno, "open %s failed", filename);
        return ISSHE_ERROR;
    }
    isshe_write(fd, default_pac_content, strlen(default_pac_content));
    isshe_close(fd);

    return ISSHE_OK;
}

isshe_int_t
isocks_mode_set()
{
    // TODO
#ifdef ISSHE_APPLE
    isocks_auto_proxy_url_set("Wi-Fi", "");
    isocks_auto_proxy_on("Wi-Fi");
#else
    isocks_auto_proxy_url_set("", ISOUT_DEFAULT_URL);
    isocks_auto_proxy_on("");
#endif

    return ISSHE_OK;
}