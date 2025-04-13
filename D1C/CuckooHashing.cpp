#include <cstdlib>
#include <ctime>

#include <cstring>
#include <iostream>
#include <fstream>

#include <openssl/err.h>

#include "CuckooHashing.hpp"



void CuckooHasing::Build_hash_table_enc_and_fill(std::unordered_map<size_t, byte_t*> raw_table, unsigned int block_len,
                            size_t hash_table_size, byte_t *hash_table, unsigned int plaintext_len,
                            size_t *seed, byte_t* enc_key) {

    size_t *hash_table_tmp1 = new size_t[hash_table_size];
    size_t *hash_table_tmp2 = new size_t[hash_table_size];

    // Build a hash table for the table keys only
    bool succeed = false;
    bool insertion_succeed = false;
    int loop_ctr = 0;
    size_t hash_val = 0;
    size_t current = 0;
    size_t swap = 0;

    unsigned int attempt = 0;

    while (succeed == false) {

        // Step 1: clean up
        for (size_t ii = 0; ii < hash_table_size; ii++)
            hash_table_tmp1[ii] = Hash_empty_flag;
        for (size_t ii = 0; ii < hash_table_size; ii++)
            hash_table_tmp2[ii] = Hash_empty_flag;
            
        // Step 2: get a new seed
        std::srand(std::time(0));
        seed[0] = std::rand();
        seed[1] = std::rand();
        
        // Step 3: insert the keys one by one
        // Insert one by one
        for (auto kvp: raw_table)
        {
            current = kvp.first;
            insertion_succeed = false;
            loop_ctr = 0;
            while ((insertion_succeed == false) || (loop_ctr < LOOP_MAX))
            {
                hash_val = (current * seed[0]) % hash_table_size;
                swap = hash_table_tmp1[hash_val];
                hash_table_tmp1[hash_val] = current;

                if (swap == Hash_empty_flag) {
                    insertion_succeed = true;
                    break;
                }

                current = swap;
                hash_val = (current * seed[1]) % hash_table_size;
                swap = hash_table_tmp2[hash_val];
                hash_table_tmp2[hash_val] = current;

                if (swap == Hash_empty_flag) {
                    insertion_succeed = true;
                    break;
                }

                loop_ctr ++;

                if (loop_ctr == LOOP_MAX)
                    break;   
            }

            if (loop_ctr == LOOP_MAX)
                break;
        }

        if (loop_ctr < LOOP_MAX)
            succeed = true;
    }

    /* Use the temporary hash tables to insert the actual payload */
    byte_t *plaintext = (byte_t*) malloc(plaintext_len * sizeof(byte_t));
    for (int ii = 0; ii < plaintext_len; ii++)
        plaintext[ii] = 0;

    for (size_t ii = 0; ii < hash_table_size; ii++) {
        if (hash_table_tmp1[ii] != Hash_empty_flag) {
            byte_t *ciphertext = (byte_t*) malloc(block_len * sizeof(byte_t));
            AES::Encrypt(raw_table[hash_table_tmp1[ii]], plaintext_len, enc_key, ciphertext);
            std::memcpy(hash_table+ii*block_len, ciphertext, block_len);
        }
        else {
            byte_t *ciphertext = (byte_t*) malloc(block_len * sizeof(byte_t));
            AES::Encrypt(plaintext, plaintext_len, enc_key, ciphertext);
            std::memcpy(hash_table+ii*block_len, ciphertext, block_len);
        }
    }
        

    for (size_t ii = 0; ii < hash_table_size; ii++) {
        if (hash_table_tmp2[ii] != Hash_empty_flag) {
            byte_t *ciphertext = (byte_t*) malloc(block_len * sizeof(byte_t));
            AES::Encrypt(raw_table[hash_table_tmp2[ii]], plaintext_len, enc_key, ciphertext);
            std::memcpy(hash_table+ii*block_len+block_len*hash_table_size, ciphertext, block_len);
        }
        else {
            byte_t *ciphertext = (byte_t*) malloc(block_len * sizeof(byte_t));
            AES::Encrypt(plaintext, plaintext_len, enc_key, ciphertext);
            std::memcpy(hash_table+ii*block_len+block_len*hash_table_size, ciphertext, block_len);
        }
    }
}

void CuckooHasing::Lookup(byte_t *hash_table, unsigned int block_len, size_t hash_table_size,
    size_t pos1, size_t pos2, byte_t *fingerprint, byte_t *result) {
    std::memcpy(result, hash_table+pos1*block_len, block_len);

    for (size_t ii = 0; ii < fingerprint_len; ii++) {
        if (result[block_len-fingerprint_len+ii] != fingerprint[ii])
        {
            std::memcpy(result, hash_table+pos2*block_len+block_len*hash_table_size, block_len);
            return;
        }
    }
}

void CuckooHasing::LookupDouble(byte_t *hash_table, unsigned int block_len, size_t hash_table_size, size_t pos1, size_t pos2, byte_t *result) {
    std::memcpy(result, hash_table+pos1*block_len, block_len);
    std::memcpy(result+block_len, hash_table+pos2*block_len+block_len*hash_table_size, block_len);
}

void CuckooHasing::LookupDoubleSSD(std::string filename, unsigned int block_len, size_t hash_table_size, size_t pos1, size_t pos2, byte_t *result) {
    std::ifstream inputFile(filename, std::ifstream::binary | std::ifstream::in);
    inputFile.seekg(pos1*block_len, inputFile.beg);
    inputFile.read((char *)result, block_len);

    inputFile.seekg(pos2*block_len+block_len*hash_table_size, inputFile.beg);
    inputFile.read((char *)result+block_len, block_len);
    result = (byte_t *) result;
    inputFile.close();
}