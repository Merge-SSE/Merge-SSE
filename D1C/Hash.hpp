#ifndef HASH_H
#define HASH_H

#include "Types.hpp"

const unsigned int PRF_key_len = 32;
const unsigned int digest_len = 32;

class Hash{
    public:
        static void HMAC_SHA256(byte_t *plaintext, int plaintext_len, byte_t *key, byte_t *digest);
        static void HMAC_SHA256_raw(byte_t *plaintext, int plaintext_len, byte_t *digest);
};


#endif