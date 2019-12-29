

#include "isshe_file.h"
#include "isshe_json.h"
#include "isshe_unistd.h"

#include "iconfig.h"


void iconfig_parse(iconfig_t *conf, const char *file)
{
    isshe_fd_t          fd;
    ssize_t             len;
    char                *buf;
    
    // 打开文件
    fd = isshe_open(file, ISSHE_FILE_RDONLY);

    // 读取文件
    buf = isshe_read_all(fd, &len);
    if (!buf) {
        printf("icnfig_parse error: isshe_read_all\n");
        exit(0);
    }
    // 解析json
    isshe_json_t* json = isshe_json_parse(buf);
    if (json->type == ISSHE_JSON_NULL) {
        printf("icnfig_parse error: json parse failed\n");
        exit(0);
    }

    isshe_free(buf);
    buf = isshe_json_print(json);
    printf("%s\n", buf);

    isshe_json_delete(json);
    isshe_free(buf);
    isshe_close(fd);
}

