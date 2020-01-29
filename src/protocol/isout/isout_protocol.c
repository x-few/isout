
#include "isout_protocol.h"


/*
 * 一次加一个，返回加的这个选项的长度。
 * 预期用法是：
 * buf = [], i = 0;
 * i += append(buf + i);
 */
isshe_size_t isout_option_append(isshe_char_t *buf,
    isshe_uint8_t type, isshe_uint8_t len, const void *data)
{
    if (!buf) {
        return ISSHE_FAILURE;
    }

    isout_option_t *option = (isout_option_t *)buf;
    option->type = type;
    option->len = len;
    if (len) {
        isshe_memcpy(option->data, data, option->len);
    }
    return sizeof(type) + sizeof(len) + len;
}


void isout_option_init_with_end(isshe_char_t *buf)
{
    isout_option_t option;
    
    option.type = ISOUT_OPTION_END;
    option.len = 0;

    isshe_memcpy(buf, &option, sizeof(option.type) + sizeof(option.len));
}

// TODO 不够健壮，只考虑了正常已初始化的情况
isshe_int_t isout_option_find(isshe_char_t *buf, isshe_uint8_t type)
{
    isshe_int_t i;
    isout_opt_t *opt;

    i = 0;
    while(i < ISOUT_ALL_OPT_MAX_LEN) {
        option = (isout_option_t *)(buf + i);
        if (option->type == type) {
            return i;
        } else if (option->type == ISOUT_OPTION_END) {
            return ISSHE_FAILURE;
        }
        i += option->len + sizeof(option->len) + sizeof(option->type);
    } 
}


isshe_int_t isout_option_find_end(isshe_char_t *buf)
{
    return isout_option_find(buf, ISOUT_OPTION_END);
}


/*
 * 插入到end选项之前
 */
isshe_int_t isout_option_insert(isshe_char_t *buf, isshe_uint8_t type, isshe_uint8_t len, const void *data)
{
    isshe_int_t end_pos = isout_option_find_end(buf);
    if (end_pos == ISSHE_FAILURE) {
        printf("find end error!!!\n");
        return ;
    }

    end_pos += isout_option_append(buf + end_pos, type, len, data);
    end_pos += isout_option_append(buf + end_pos, ISOUT_OPTION_END, 0, NULL);
    return end_pos
}


