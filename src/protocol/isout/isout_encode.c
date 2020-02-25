
#include "isout_encode.h"


isshe_int_t isout_encode_aes_cfb128(isshe_uchar_t *ckey, isshe_uchar_t *ivec,
    isshe_char_t *data, isshe_size_t data_len, isshe_log_t *log)
{
    isshe_aes_key_t     key;
    isshe_int_t         num = 0;
    isshe_uchar_t       ivec_cp[ISSHE_AES_BLOCK_SIZE];

    if (!ckey || !ivec || !data) {
        isshe_log_error(log, "isout_encode_aes_cfb128: invalid parameters");
        return ISSHE_ERROR;
    }
    // copy ivec, because isshe_aes_cfb128_encrypt will change ivec
    isshe_memcpy(ivec_cp, ivec, ISSHE_AES_BLOCK_SIZE);

    isshe_aes_set_encrypt_key(ckey, ISSHE_AES_BLOCK_SIZE_BIT, &key);

    //isshe_log_debug(log, "before encode: ivec = %s, data = (%d)%s", ivec_cp, data_len, data);
    isshe_aes_cfb128_encrypt((const unsigned char *)data,
        (unsigned char *)data, data_len, &key, ivec_cp, &num, ISSHE_AES_ENCRYPT);
    //isshe_log_debug(log, "after encode: ivec = %s, data = (%d)%s", ivec_cp, data_len, data);
    return ISSHE_OK;
}


isshe_int_t
isout_encode(isshe_int_t algo, isshe_char_t *key, isshe_char_t *iv,
    isshe_char_t *data, isshe_int_t data_len, isshe_log_t *log)
{
    // 判断加密算法，使用相应的解密方式
    if (algo == ISOUT_CRYPTO_ALGO_AES_128_CFB) {
        return isout_encode_aes_cfb128(
            (unsigned char *)key,
            (unsigned char *)iv, data, data_len, log);
    }

    return ISSHE_OK;
}

