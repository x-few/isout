#include "isout_protocol.h"

isout_options_t *
isout_options_create(isshe_mempool_t *mempool, isshe_log_t *log)
{
    isout_options_t *opts;

    opts = isshe_mpalloc(mempool, sizeof(isout_options_t));
    if (!opts) {
        isshe_log_alert(log, "mpalloc isout options failed");
        return NULL;
    }

    // init
    isshe_memzero(opts, sizeof(isout_options_t));

    return opts;
}


void isout_options_destroy(isout_options_t *opts, isshe_mempool_t *mempool)
{
    isshe_mpfree(mempool, opts, sizeof(isout_options_t));
}


isshe_int_t
isout_options_from_string(
    isout_options_t *options,
    isshe_char_t *options_str,
    isshe_mempool_t *mempool,
    isshe_log_t *log)
{
    isout_option_t  *opt;
    isshe_int_t     index;

    if (!options || !options_str) {
        isshe_log_alert(log, "parse isout options failed: invalid parameters");
        return ISSHE_FAILURE;
    }

    do {
        opt = (isout_option_t *)(options_str + index);
        switch (opt->type)
        {
        case ISOUT_OPTION_COUNT:
            options->count = ntohll(*(uint64_t *)opt->data);
            break;
        case ISOUT_OPTION_RANDOM:
            options->random = ntohl(*(uint32_t *)opt->data);
            break;
        case ISOUT_OPTION_DOMAIN:
            if (!options->dname) {
                options->dname_len = opt->len;
                options->dname = isshe_strdup_mp(
                    (isshe_char_t *)opt->data, opt->len, mempool);
            }
            isshe_log_debug(log, "---isshe---: isout_options_from_string---3---");
            break;
        case ISOUT_OPTION_IPV6:
            isshe_log_debug(log, "---isshe---: isout_options_from_string---4---");
            if (!options->ipv6) {
                options->ipv6_len = opt->len;
                options->ipv6 = isshe_strdup_mp(
                    (isshe_char_t *)opt->data, opt->len, mempool);
            }
            isshe_log_debug(log, "---isshe---: isout_options_from_string---5---");
            break;
        case ISOUT_OPTION_IPV4:
            options->ipv4 = ntohl(*(uint32_t *)opt->data);      // 大端转主机
            break;
        case ISOUT_OPTION_PORT:
            options->port = ntohs(*(uint16_t *)opt->data);
            break;
        case ISOUT_OPTION_ADDR_TYPE:
            options->addr_type = opt->data[0];
            break;
        case ISOUT_OPTION_DATA_LEN:
            options->data_len = ntohl(*(uint32_t *)opt->data);
            break;
        case ISOUT_OPTION_CRYPTO_ALGO:
            break;
        case ISOUT_OPTION_CRYPTO_KEY:
            break;
        case ISOUT_OPTION_CRYPTO_IV:
            break;
        default:
            break;
        }
        index += sizeof(opt->type) + sizeof(opt->len) + opt->len;
    } while(opt->type != ISOUT_OPTION_END);

    isshe_log_debug(log, "---isshe---: isout_options_from_string---6---");
    return ISSHE_SUCCESS;
}


isshe_int_t isout_options_len(isout_options_t *opts)
{
    isshe_int_t len;
    isout_option_t opt;

    len = 0;
    if (opts->count != 0) {
        len += sizeof(isshe_uint64_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->random != 0) {
        len += sizeof(isshe_uint32_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->dname && opts->dname_len != 0) {
        len += opts->dname_len
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->ipv6 && opts->ipv6_len != 0) {
        len += opts->ipv6_len
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->ipv4 != 0) {
        len += sizeof(isshe_uint32_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->port != 0) {
        len += sizeof(isshe_uint16_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->addr_type != 0) {
        len += sizeof(isshe_uint8_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->data_len != 0) {
        len += sizeof(isshe_uint32_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    // END OPTION
    len += sizeof(opt.type) + sizeof(opt.len);

    return len;
}


isshe_char_t *
isout_options_to_string(isout_options_t *opts,
    isshe_mempool_t *mempool, isshe_size_t *stropts_len)
{
    // 计算所有OPTION长度
    isshe_int_t     len;
    isshe_char_t    *stropts;
    isshe_char_t    *tmp;
    isout_option_t  opt;
    isshe_uint16_t  ui16;
    isshe_uint32_t  ui32;
    isshe_uint64_t  ui64;
    
    len = isout_options_len(opts);
    if (len == 0) {
        return NULL;
    }

    // 分配内存
    stropts = (isshe_char_t *)isshe_mpalloc(mempool, len);
    if (!stropts) {
        return NULL;
    }

    tmp = stropts;
    // 进行tostring
    if (opts->count != 0) {
        ui64 = htonll(opts->count);
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_COUNT, sizeof(opts->count), &ui64);
    }

    if (opts->random != 0) {
        ui32 = htonl(opts->random);
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_RANDOM, sizeof(opts->random), &ui32);
    }

    if (opts->dname && opts->dname_len != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_DOMAIN, opts->dname_len, opts->dname);
    }

    if (opts->ipv6 && opts->ipv6_len != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_IPV6, opts->ipv6_len, opts->ipv6);
    }

    if (opts->ipv4 != 0) {
        ui32 = htonl(opts->ipv4);
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_IPV4, sizeof(opts->ipv4), &ui32);
    }

    if (opts->port != 0) {
        ui16 = htons(opts->port);
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_PORT, sizeof(opts->port), &ui16);
    }

    if (opts->addr_type != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_ADDR_TYPE, sizeof(opts->addr_type), &opts->addr_type);
    }

    if (opts->data_len != 0) {
        ui32 = htonl(opts->data_len);
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_DATA_LEN, sizeof(opts->data_len), &ui32);
    }

    // END OPTION
    tmp += isout_option_append(tmp, ISOUT_OPTION_END, 0, NULL);

    *stropts_len = len;

    return stropts;
}


void
isout_options_print(isout_options_t *opts, isshe_log_t *log)
{
    isshe_log_info(log, "======================================");
    isshe_log_info(log, "isout options: ");
    if (opts->count != 0) {
        isshe_log_info(log, " - count: %d", opts->count);
    }

    if (opts->random != 0) {
        isshe_log_info(log, " - random: %lld", opts->random);
    }

    if (opts->dname && opts->dname_len != 0) {
        isshe_log_info(log, " - dname: (%d)%s", opts->dname_len, opts->dname);
    }

    if (opts->ipv6 && opts->ipv6_len != 0) {
        isshe_log_info(log, " - ipv6: (%d)%s", opts->ipv6_len, opts->ipv6);
    }

    if (opts->ipv4 != 0) {
        isshe_log_info(log, " - ipv4: %u", opts->ipv4);
    }

    if (opts->port != 0) {
        isshe_log_info(log, " - port: %u", opts->port);
    }

    if (opts->addr_type != 0) {
        isshe_log_info(log, " - addr_type: %u", opts->addr_type);
    }

    if (opts->data_len != 0) {
        isshe_log_info(log, " - data_len: %u", opts->data_len);
    }

    isshe_log_info(log, "======================================");
}

isshe_size_t
isout_options_string_len(isshe_char_t *buf, isshe_size_t buflen)
{
    isout_option_t  opt;
    isshe_size_t    len;

    len = isout_option_find_end(buf, buflen);
    if (len == ISSHE_FAILURE) {
        return ISSHE_FAILURE;
    }

    return (len + sizeof(opt.type) + sizeof(opt.len));
}

isshe_bool_t
isout_options_is_complete(isshe_char_t *buf, isshe_size_t buflen)
{
    if (isout_options_string_len(buf, buflen) == ISSHE_FAILURE) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}