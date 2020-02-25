
#include "isout_protocol.h"
#include "isout_options.h"

void
isout_protocol_header_set(
    isout_protocol_header_t *header,
    isshe_uint16_t opts_len, isshe_uint16_t data_len)
{
    header->opts_len = htons(opts_len);
    header->data_len = htons(data_len);
}


void isout_protocol_header_get(
    isout_protocol_header_t *dst, isout_protocol_header_t *src)
{
    dst->opts_len = ntohs(src->opts_len);
    dst->data_len = ntohs(src->data_len);
}

isshe_bool_t
isout_protocol_header_is_valid(isout_protocol_header_t *hdr)
{
    isshe_int_t     tmp;
    tmp = ntohs(hdr->opts_len);
    if (tmp < 0 || tmp > ISOUT_PROTOCOL_OPTIONS_LEN_MAX) {
        return ISSHE_FALSE;
    }

    tmp = ntohs(hdr->data_len);
    if (tmp < 0 || tmp > ISOUT_PROTOCOL_DATA_LEN_MAX) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}

void
isout_protocol_header_print(
    isout_protocol_header_t *header, isshe_log_t *log)
{
    isshe_log_info(log, "========================================");
    isshe_log_info(log, "isout protocl header: ");
    isshe_log_info(log, "- options length   : %d", ntohs(header->opts_len));
    isshe_log_info(log, "- data length      : %d", ntohs(header->data_len));
    isshe_log_info(log, "========================================");
}


/*
 * 一次加一个，返回加的这个选项的长度。
 * 预期用法是：
 * buf = [], i = 0;
 * i += append(buf + i);
 */
isshe_size_t isout_option_append(isshe_char_t *buf,
    isshe_uint8_t type, isshe_uint8_t len, const void *data)
{
    isout_protocol_option_t *option;
    if (!buf) {
        return ISSHE_ERROR;
    }

    option = (isout_protocol_option_t *)buf;
    option->type = type;
    option->len = len;
    if (len) {
        isshe_memcpy(option->data, data, option->len);
    }
    return sizeof(type) + sizeof(len) + len;
}


isshe_size_t
isout_option_init_with_end(isshe_char_t *buf)
{
    return isout_option_append(buf, ISOUT_OPTION_END, 0, NULL);
}

// TODO 不够健壮，只考虑了正常已初始化的情况
isshe_int_t isout_option_find(isshe_char_t *buf,
    isshe_size_t buflen, isshe_uint8_t type)
{
    isshe_int_t                 i;
    isout_protocol_option_t     *option;

    i = 0;
    while(i < buflen) {
        option = (isout_protocol_option_t *)(buf + i);
        if (option->type == type) {
            return i;
        } else if (option->type == ISOUT_OPTION_END) {
            return ISSHE_ERROR;
        }
        i += option->len + sizeof(option->len) + sizeof(option->type);
    }

    return ISSHE_ERROR;
}


isshe_int_t isout_option_find_end(isshe_char_t *buf, isshe_size_t buflen)
{
    return isout_option_find(buf, buflen, ISOUT_OPTION_END);
}


/*
 * 插入到end选项之前
 */
isshe_int_t
isout_option_insert(isshe_char_t *buf, isshe_size_t buflen,
    isshe_uint8_t type, isshe_uint8_t len, const void *data)
{
    isshe_int_t end_pos = isout_option_find_end(buf, buflen);
    if (end_pos == ISSHE_ERROR) {
        return ISSHE_ERROR;
    }

    end_pos += isout_option_append(buf + end_pos, type, len, data);
    end_pos += isout_option_append(buf + end_pos, ISOUT_OPTION_END, 0, NULL);
    return end_pos;
}


