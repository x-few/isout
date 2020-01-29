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
isout_options_from_string(isout_options_t *options,
    isshe_char_t *options_str, isshe_mempool_t *mempool, isshe_log_t *log)
{
    isout_option_t  *opt;
    isshe_int_t     index;

    if (!options || !options_str) {
        isshe_log_alert("parse isout options failed: invalid parameters");
        return ISSHE_FAILURE;
    }

    do {
        opt = (isout_option_t *)options_str + index;
        switch (opt->type)
        {
        case ISOUT_OPTION_COUNT:
            options->count = ntohll(*(uint64_t *)opt->data);
            break;
        case ISOUT_OPTION_RANDOM:
            options->random = ntohl(*(uint32_t *)opt->data);
            break;
        case ISOUT_OPTION_DOMAIN:
            options->dname_len = opt->len;
            options->dname =(isshe_uint8_t *)
                isshe_strdup_mp(opt->data, opt->len, mempool);
            break;
        case ISOUT_OPTION_IPV6:
            options->ipv6_len = opt->len;
            options->ipv6 = (isshe_uint8_t *)
                isshe_strdup_mp(opt->data, opt->len, mempool);
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
            options->data_len = ntohs(*(uint16_t *)opt->data);
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

    return ISSHE_SUCCESS;
}

isshe_int_t
isout_options_string_len(isshe_char_t *buf)
{
    isout_option_t option;
    return (isout_option_find_end(buf)
        + sizeof(option.len) + sizeof(option.type));
}

isshe_int_t isout_options_len(isout_options_t *opts)
{
    isshe_int_t len;
    isout_option_t opt;

    len = 0;
    opt_count = 0;
    if (opts->count != 0) {
        len += sizeof(isshe_uint64_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->random != 0) {
        len += sizeof(isshe_uint32_t)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->dname && opts->dname_len != 0) {
        len += sopts->dname_len
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
    isshe_int_t len;
    isshe_char_t *stropts;
    isshe_char_t *tmp;
    isout_option_t opt;
    
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
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_COUNT, sizeof(opts->count), &opts->count);
    }

    if (opts->random != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_RANDOM, sizeof(opts->random), &opts->random);
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
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_IPV4, sizeof(opts->ipv4), &opts->ipv4);
    }

    if (opts->port != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_PORT, sizeof(opts->port), &opts->port);
    }

    if (opts->addr_type != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_ADDR_TYPE, sizeof(opts->addr_type), &opts->addr_type);
    }

    if (opts->data_len != 0) {
        tmp += isout_option_append(tmp,
            ISOUT_OPTION_DATA_LEN, sizeof(opts->data_len), &opts->data_len);
    }

    // END OPTION
    tmp += isout_option_append(tmp, ISOUT_OPTION_END, 0, NULL);

    *stropts_len = len;

    return stropts;
}
