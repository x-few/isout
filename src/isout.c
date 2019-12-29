


#include <stdio.h>

#include "isout.h"
#include "iconfig.h"

int main()
{
    // 解析config
    char *cfile = "../config/config.json";
    iconfig_t config;

    iconfig_parse(&config, cfile);

    // 配置log

    // master接管进程
}