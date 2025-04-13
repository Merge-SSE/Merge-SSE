#include<algorithm>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "AES.hpp"

#include "randombytes.hpp"


using namespace std;

// Generate a random IV
void AES::GenerateIV(byte_t* iv) {
    randombytes(iv, IV_len);
    
    //std::memset(iv, 0, IV_len);
    //RAND_priv_bytes(iv, IV_len);

    /*
    RAND_poll();
    if (RAND_bytes(iv, IV_len) != 1) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    */
}

// Encrypt a message, the IV is generated internally the ciphertext is (ct || IV)
int AES::Encrypt(byte_t *plaintext, int plaintext_len, byte_t *key, byte_t *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        HandleErrors();

    /* Initialise the initialization vector */
    byte_t iv[IV_len]; //= {0};
    GenerateIV(iv);

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        HandleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        HandleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext byte_ts may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        HandleErrors();
    ciphertext_len += len;

    /* Appending IV to the ciphertext */
    std::copy(iv, iv+IV_len, ciphertext+ciphertext_len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Decrypt a message, the IV is the last IV_len byte_ts of ciphertext
int AES::Decrypt(byte_t *ciphertext, int plaintext_len, byte_t *key, byte_t *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len_local;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        HandleErrors();

    /* Extract IV */
    byte_t iv[IV_len] = {};
    std::copy(ciphertext+plaintext_len, ciphertext+plaintext_len+IV_len, iv);

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        HandleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, plaintext_len))
        HandleErrors();
    plaintext_len_local = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        HandleErrors();
    plaintext_len_local += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len_local;
}



// Output OpenSSL error to stderr and abort
void AES::HandleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}