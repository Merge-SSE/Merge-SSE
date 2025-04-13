#ifndef AES_H
#define AES_H

const unsigned int enc_key_len = 16;
const unsigned int IV_len = 16;

#include "Types.hpp"

class AES {
    public:
        /* Generate a random IV */ 
        static void GenerateIV(byte_t *iv);

        /* Encrypt a message, the IV is generated internally the ciphertext is (ct || IV) */
        static int Encrypt(byte_t *plaintext, int plaintext_len, byte_t *key, byte_t *ciphertext);

        /* Decrypt a message, the IV is the last IV_len bytes of ciphertext */
        static int Decrypt(byte_t *ciphertext, int ciphertext_len, byte_t *key, byte_t *plaintext);

        static void HandleErrors();
};

#endif