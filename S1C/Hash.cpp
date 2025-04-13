#include "Utilities.hpp"

#include <openssl/hmac.h>

#include "Hash.hpp"

void Hash::HMAC_SHA256(byte_t *plaintext, int plaintext_len, byte_t *key, byte_t *digest) {
    unsigned int md_len;
    HMAC(EVP_sha256(), key, 32, plaintext, plaintext_len, digest, &md_len);
}

void Hash::HMAC_SHA256_raw(byte_t *plaintext, int plaintext_len, byte_t *digest) {
    unsigned int md_len;
    HMAC(EVP_sha256(), nullptr, 0, plaintext, plaintext_len, digest, &md_len);
}
