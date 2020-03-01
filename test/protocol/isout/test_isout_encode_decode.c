#include "isshe_common.h"
#include "isout_encode.h"
#include "isout_decode.h"
#include "isout_protocol.h"
#include "isout_options.h"

void test1()
{
    isout_protocol_options_t opts;
    isshe_log_t     *log;
    isshe_char_t    data[] = "isshe&chudai";
    isshe_size_t    data_len = strlen(data);

    log = isshe_log_instance_get(7, NULL, NULL);
    if (!log) {
        printf("log == NULL");
        return ;
    }

    opts.session_crypto_algo = 1;
    opts.session_crypto_iv = "1234567890abcdef";
    opts.session_crypto_key = "abcdef1234567890";
    
    isout_encode(opts.session_crypto_algo,
        opts.session_crypto_key,
        opts.session_crypto_iv,
        data, data_len, log);

    isout_decode(opts.session_crypto_algo,
        opts.session_crypto_key,
        opts.session_crypto_iv,
        data, data_len, log);
}


int main()
{
    test1();
}