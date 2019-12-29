#ifndef _ISSHE_ISOUT_IUSER_H_
#define _ISSHE_ISOUT_IUSER_H_

#include <stdint.h>

#define IUSER_NAME_PWD_MAX_LEN 32

struct iuser_s
{
    // 测试使用明文，后面加密后保存
    uint8_t username[IUSER_NAME_PWD_MAX_LEN];   // aes(md5(username))
    uint8_t userpwd[IUSER_NAME_PWD_MAX_LEN];    // aes(md5(userpwd))
};

typedef struct iuser_s iuser_t;

#endif