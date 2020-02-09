#include "isout_options.h"

isout_protocol_options_t *
isout_protocol_options_create(isshe_mempool_t *mempool, isshe_log_t *log)
{
    isout_protocol_options_t *opts;

    opts = isshe_mpalloc(mempool, sizeof(isout_protocol_options_t));
    if (!opts) {
        isshe_log_alert(log, "mpalloc isout options failed");
        return NULL;
    }

    // init
    isshe_memzero(opts, sizeof(isout_protocol_options_t));

    return opts;
}


void isout_protocol_options_destroy(
    isout_protocol_options_t *opts, isshe_mempool_t *mempool)
{
    isshe_mpfree(mempool, opts, sizeof(isout_protocol_options_t));
}

isout_protocol_header_t *
isout_protocol_header_create(isshe_mempool_t *mempool, isshe_log_t *log)
{
    isout_protocol_header_t *opts;

    opts = isshe_mpalloc(mempool, sizeof(isout_protocol_header_t));
    if (!opts) {
        isshe_log_alert(log, "mpalloc isout header failed");
        return NULL;
    }

    // init
    isshe_memzero(opts, sizeof(isout_protocol_header_t));

    return opts;
}


void isout_protocol_header_destroy(
    isout_protocol_header_t *opts, isshe_mempool_t *mempool)
{
    isshe_mpfree(mempool, opts, sizeof(isout_protocol_header_t));
}



isshe_int_t
isout_protocol_options_from_string(
    isout_protocol_options_t *options,
    isshe_char_t *stropts,
    isshe_int_t stropts_len,
    isshe_mempool_t *mempool,
    isshe_log_t *log)
{
    isout_protocol_option_t     *opt;
    isshe_int_t                 index;

    if (!options || !stropts) {
        isshe_log_alert(log, "options from string: invalid parameters");
        return ISSHE_FAILURE;
    }

    // 检查是否是完整的选项
    if (!isout_protocol_options_is_valid(stropts, stropts_len)) {
        isshe_log_alert(log, "invalid isout protocol options");
        return ISSHE_FAILURE;
    }

    do {
        opt = (isout_protocol_option_t *)(stropts + index);
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
            break;
        case ISOUT_OPTION_IPV6:
            if (!options->ipv6) {
                options->ipv6_len = opt->len;
                options->ipv6 = isshe_strdup_mp(
                    (isshe_char_t *)opt->data, opt->len, mempool);
            }
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
        case ISOUT_OPTION_SESSION_CRYPTO_ALGO:
            options->session_crypto_algo = opt->data[0];
            break;
        case ISOUT_OPTION_SESSION_CRYPTO_KEY:
            if (!options->session_crypto_key) {
                options->session_crypto_key = isshe_strdup_mp(
                    (isshe_char_t *)opt->data, opt->len, mempool);
            }
            break;
        case ISOUT_OPTION_SESSION_CRYPTO_IV:
            if (!options->session_crypto_iv) {
                options->session_crypto_iv = isshe_strdup_mp(
                    (isshe_char_t *)opt->data, opt->len, mempool);
            }
            break;
        default:
            break;
        }
        index += sizeof(opt->type) + sizeof(opt->len) + opt->len;
    } while(opt->type != ISOUT_OPTION_END);
    return ISSHE_SUCCESS;
}


isshe_int_t isout_protocol_options_len(isout_protocol_options_t *opts)
{
    isshe_int_t len;
    isout_protocol_option_t opt;

    len = 0;
    if (opts->count != 0) {
        len += sizeof(opts->count)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->random != 0) {
        len += sizeof(opts->random)
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
        len += sizeof(opts->ipv4)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->port != 0) {
        len += sizeof(opts->port)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->addr_type != 0) {
        len += sizeof(opts->addr_type)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->data_len != 0) {
        len += sizeof(opts->data_len)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->session_crypto_algo != ISOUT_CRYPTO_ALGO_UNKNOWN) {
        len += sizeof(opts->session_crypto_algo)
            + sizeof(opt.type) + sizeof(opt.len);
    }

    if (opts->session_crypto_iv) {
        switch (opts->session_crypto_algo)
        {
        case ISOUT_CRYPTO_ALGO_AES_128_CFB:
            len += ISSHE_AES_BLOCK_SIZE + sizeof(opt.type) + sizeof(opt.len);
            break;
        }
    }

    if (opts->session_crypto_key) {
        switch (opts->session_crypto_algo)
        {
        case ISOUT_CRYPTO_ALGO_AES_128_CFB:
            len += ISSHE_AES_BLOCK_SIZE + sizeof(opt.type) + sizeof(opt.len);
            break;
        }
    }

    // END OPTION
    len += sizeof(opt.type) + sizeof(opt.len);

    return len;
}


isshe_int_t
isout_protocol_options_to_string(
    isout_protocol_options_t *opts,
    isshe_char_t *stropts,
    isshe_int_t *stropts_len,
    isshe_log_t *log)
{
    // 计算所有OPTION长度
    isshe_int_t                 len;
    isshe_char_t                *tmp;
    //isout_protocol_option_t     opt;
    isshe_uint16_t              ui16;
    isshe_uint32_t              ui32;
    isshe_uint64_t              ui64;

    len = isout_protocol_options_len(opts);
    if (len == 0 || len > ISOUT_PROTOCOL_OPTIONS_LEN_MAX) {
        isshe_log_error(log, "isout protocol options length = %d", len);
        return ISSHE_FAILURE;
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

    if (opts->session_crypto_algo != ISOUT_CRYPTO_ALGO_UNKNOWN) {
        tmp += isout_option_append(
            tmp, ISOUT_OPTION_SESSION_CRYPTO_ALGO,
            sizeof(opts->session_crypto_algo), &opts->session_crypto_algo);
    }

    if (opts->session_crypto_iv) {
        switch (opts->session_crypto_algo)
        {
        case ISOUT_CRYPTO_ALGO_AES_128_CFB:
            tmp += isout_option_append(
                tmp, ISOUT_OPTION_SESSION_CRYPTO_IV,
                ISSHE_AES_BLOCK_SIZE, opts->session_crypto_iv);
            break;
        }
    }

    if (opts->session_crypto_key) {
        switch (opts->session_crypto_algo)
        {
        case ISOUT_CRYPTO_ALGO_AES_128_CFB:
            tmp += isout_option_append(
                tmp, ISOUT_OPTION_SESSION_CRYPTO_KEY,
                ISSHE_AES_BLOCK_SIZE, opts->session_crypto_key);
            break;
        }
    }

    // END OPTION
    tmp += isout_option_append(tmp, ISOUT_OPTION_END, 0, NULL);

    *stropts_len = len;

    return ISSHE_SUCCESS;
}


void
isout_protocol_options_print(isout_protocol_options_t *opts, isshe_log_t *log)
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

    if (opts->session_crypto_algo) {
        isshe_log_info(log, " - session_crypto_algo: %u", opts->session_crypto_algo);
    }

    if (opts->session_crypto_key) {
        isshe_log_info(log, " - session_crypto_key: %s", opts->session_crypto_key);
    }

    if (opts->session_crypto_iv) {
        isshe_log_info(log, " - session_crypto_iv: %s", opts->session_crypto_iv);
    }


    isshe_log_info(log, "======================================");
}

isshe_int_t
isout_protocol_options_string_len(isshe_char_t *buf, isshe_int_t buflen)
{
    isout_protocol_option_t  opt;
    isshe_int_t    len;

    len = isout_option_find_end(buf, buflen);
    if (len == ISSHE_FAILURE) {
        return ISSHE_FAILURE;
    }

    return (len + sizeof(opt.type) + sizeof(opt.len));
}

isshe_bool_t
isout_protocol_options_is_valid(isshe_char_t *buf, isshe_int_t buflen)
{
    if (isout_protocol_options_string_len(buf, buflen) == ISSHE_FAILURE) {
        return ISSHE_FALSE;
    }

    return ISSHE_TRUE;
}

isshe_int_t
isout_protocol_send_opts_generate(
    isout_protocol_options_t *send, 
    isout_protocol_options_t *all,
    isshe_addr_info_t *addrinfo,
    isshe_mempool_t *mempool,
    isshe_log_t *log)
{
    isshe_char_t        *key;
    isshe_char_t        *iv;

    if (!all->session_crypto_key && !all->session_crypto_iv) {
        key = isshe_mpalloc(mempool, ISSHE_AES_BLOCK_SIZE);
        iv = isshe_mpalloc(mempool, ISSHE_AES_BLOCK_SIZE);
        if (!key || !iv) {
            isshe_log_error(log, "mpalloc key or iv failed");
            return ISSHE_FAILURE;
        }

        // TODO 填充key/iv
        isshe_memcpy(key, "abcdef1234567890", 16);
        isshe_memcpy(iv, "1234567890abcdef", 16);

        all->session_crypto_algo = ISOUT_CRYPTO_ALGO_AES_128_CFB;
        all->session_crypto_key = key;
        all->session_crypto_iv = iv;

        send->session_crypto_algo = all->session_crypto_algo;
        send->session_crypto_key = all->session_crypto_key;
        send->session_crypto_iv = all->session_crypto_iv;
    }

    if (!all->dname && addrinfo->addr_text) {
        all->dname = addrinfo->addr_text;
        all->dname_len = addrinfo->addr_len;
        all->port = addrinfo->port;

        send->dname = all->dname;
        send->dname_len = all->dname_len;
        send->port = all->port;
    }

    return ISSHE_SUCCESS;
}

void
isout_protocol_send_opts_resume(
    isout_protocol_options_t *send, 
    isout_protocol_options_t *all,
    isshe_mempool_t *mempool,
    isshe_log_t *log)
{
    if (send->session_crypto_key) {
        isshe_mpfree(mempool, all->session_crypto_key, ISSHE_AES_BLOCK_SIZE);
        isshe_mpfree(mempool, all->session_crypto_iv, ISSHE_AES_BLOCK_SIZE);

        all->session_crypto_algo = ISOUT_CRYPTO_ALGO_UNKNOWN;
        all->session_crypto_key = NULL;
        all->session_crypto_iv = NULL;

        send->session_crypto_algo = all->session_crypto_algo;
        send->session_crypto_key = all->session_crypto_key;
        send->session_crypto_iv = all->session_crypto_iv;
    }
}