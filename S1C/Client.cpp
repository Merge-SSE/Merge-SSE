#include <cmath>
#include <iostream>
#include <fstream>
#include <cstring>
#include <iterator>
#include <algorithm>

#include <openssl/err.h>

#include "Client.hpp"
#include "CuckooHashing.hpp"
#include "Utilities.hpp"
#include "randombytes.hpp"


/* 
 * Generate the keys for S1C
 * Keys include:
 *   1. 256-bit PRF key used by HMAC-SHA256 to generate subkeys for each keyword.
 *   2. 128-bit encryption key for the payloads 
 */
void Client::KeyGen(){
    randombytes(this->PRF_key, PRF_key_len);
    randombytes(this->enc_key, enc_key_len);
}


/*
 * Read input file and parse it as mmap_plaintext
 */
void Client::ReadMM(std::string filename) {
    std::ifstream inputFile(filename);

    this->N_KDP = 0;
    
    if (inputFile.is_open()) {
        std::string line;
        size_t pos = 0;
        while (getline(inputFile, line)) {
            /* Get the keyword */
            pos = line.find(",");
            std::string keyword = line.substr(0, pos);
            line.erase(0, pos + 1);

            /* Get the document identifiers */
            std::vector<std::string> values;
            while ((pos = line.find(",")) != std::string::npos) {
                std::string value = line.substr(0, pos);
                values.push_back(value);
                line.erase(0, pos + 1);
            }
            std::string value = line.substr(0, pos);
            values.push_back(value);

            if (keyword.length() > S1C_data_size)
                continue;

            this->mmap_plaintext[keyword] = values;
            this->N_KDP += values.size();
        }
        inputFile.close();
    }

    /* Obtain the number of keywords (M) and the number of keyword document pairs (N) */
    this->N_keywords = this->mmap_plaintext.size();
    this->usable_slots = (page_size - S1C_emm_len_index_len - IV_len) / S1C_data_size;

    /* Compute the number of partial emms and bincap */
    this->bincap = (size_t) (bincap_const * logLogLambda * this->usable_slots * std::log(this->N_KDP / this->usable_slots));
    this->N_bins = (size_t) std::ceil((double) this->N_KDP / ( logLogLambda * this->usable_slots * std::log(this->N_KDP / this->usable_slots)));

    /* Allocate emm_partial_raw */
    this->emm_partial_raw = new std::unordered_map<size_t, byte_t*>[this->N_bins];
    this->seed_emm_partial = (size_t *) malloc(2 * this->N_bins * sizeof(size_t));

    std::cout << "Index read." << std::endl;

    std::cout << "Total pages: " << std::ceil(this->N_KDP / this->usable_slots) << std::endl;
    std::cout << "Usable slots per page: " << this->usable_slots << std::endl;
    std::cout << "Bincap partial (raw): " << this->bincap << std::endl;
    std::cout << "N_bins partial: " << this->N_bins << std::endl;
    std::cout << "---------------------" << std::endl;
}

/* 
    * Setup of S1C
    * No input required (plaintext multimap is obtained using readMM(); all other inputs can be derived from mmap_plaintext)
    * Outputs:
    *   1. emm_len_raw: encrypted query response length of each keyword
    *   2. emm_full_raw: encrypted values that fill the pages
    *   3. N_bins: The number of bins
    *   4. bincap: The capacity of each bin
    *   5. emm_partial_raw: encrypted values (one by one) that do not fill a page.
    */
void Client::Setup() {

    for (const auto& pair : this->mmap_plaintext) {
        /* Figure out how many full pages  */
        size_t val_len = pair.second.size();
        size_t page_count = std::ceil((double) val_len / this->usable_slots);
        size_t last_page_offset = (val_len % this->usable_slots == 0) ? 0: 1;

        /* Build emm_len_raw */
        /* Generate the keys for the MM key */
        byte_t emm_len_index[S1C_emm_len_index_len];
        byte_t emm_len_XOR_key[S1C_emm_len_XOR_key_len];
        byte_t token[digest_len];
        this->SearchTokenGen(pair.first, emm_len_index, emm_len_XOR_key, token);

        /* Encrypt the query response volume and pad the ciphertext with the MM key */
        byte_t *emm_len_ciphertext = (byte_t *) malloc((S1C_emm_len_XOR_key_len+S1C_emm_len_index_len) * sizeof(byte_t));
        std::memcpy(emm_len_ciphertext, &val_len, sizeof(size_t));
        std::memcpy(emm_len_ciphertext+S1C_emm_len_XOR_key_len, emm_len_index, S1C_emm_len_index_len);

        for (int ii = 0; ii < S1C_emm_len_XOR_key_len; ii++)
            emm_len_ciphertext[ii] ^= emm_len_XOR_key[ii];

        /* Parse the first 8 bytes of emm_len_index as size_t and store the emm_len_raw entry */
        size_t emm_len_index_int = 0;
        std::memcpy(&emm_len_index_int, emm_len_index, sizeof(size_t));
        this->emm_len_raw[emm_len_index_int] = emm_len_ciphertext;

        /* Build emm_full_raw */
        std::vector<std::string>::const_iterator mm_value_iterator = pair.second.begin();
        
        byte_t hash_input_pages[sizeof(size_t) + digest_len];
        size_t emm_full_page_index_int = 0;
        byte_t digest[digest_len];

        std::memcpy(hash_input_pages+sizeof(size_t), token, digest_len);

        for (size_t jj = 0; jj < page_count - last_page_offset; jj++) {
            /* Compute the emm key for the jj-th page */
            std::memcpy(hash_input_pages, &jj, sizeof(size_t));
            Hash::HMAC_SHA256_raw(hash_input_pages, sizeof(size_t) + digest_len, digest);

            /* dump mm values into the plaintext */
            byte_t *plaintext = (byte_t *) calloc(S1C_data_size*this->usable_slots, sizeof(byte_t));
            for (size_t ii = 0; ii < this->usable_slots; ii++) {
                std::memcpy(plaintext+ii*S1C_data_size, mm_value_iterator->c_str(), mm_value_iterator->length());
                ++mm_value_iterator;
            }

            /* Encryption */
            byte_t *emm_full_ciphertext = (byte_t *) malloc(page_size * sizeof(byte_t));
            AES::Encrypt(plaintext, S1C_data_size*this->usable_slots, enc_key, emm_full_ciphertext);
            free(plaintext);

            /* Add emm_full_index to the ciphertext in the end as a fingerprint */
            std::memcpy(emm_full_ciphertext+S1C_data_size*this->usable_slots+IV_len, digest, fingerprint_len);

            
            std::memcpy(&emm_full_page_index_int, digest, sizeof(size_t));
            this->emm_full_raw[emm_full_page_index_int] = emm_full_ciphertext;
        }

        /* Build emm_partial_raw */
        if (val_len % this->usable_slots != 0) {
            // Get the last "page index"
            std::memcpy(hash_input_pages, &page_count, sizeof(size_t));
            Hash::HMAC_SHA256_raw(hash_input_pages, sizeof(size_t) + digest_len, digest);
            
            // Hash again to get the partial page index
            byte_t partial_index_byte[digest_len];
            Hash::HMAC_SHA256_raw(digest, digest_len, partial_index_byte);

            // Parse the partial page index as an integer
            size_t emm_partial_index;
            std::memcpy(&emm_partial_index, partial_index_byte, sizeof(size_t));
            emm_partial_index = emm_partial_index % this->N_bins;


            byte_t hash_input_partial[sizeof(size_t)*2 + digest_len];
            size_t emm_partial_index_inner_int = 0;
            std::memcpy(hash_input_partial, &page_count, sizeof(size_t));
            std::memcpy(hash_input_partial+2*sizeof(size_t), token, digest_len);

            for (size_t jj = 0; jj < val_len % this->usable_slots; jj++) {
                // Get the index in the emm_partial_raw[emm_partial_index]
                std::memcpy(hash_input_partial+sizeof(size_t), &jj, sizeof(size_t));
                Hash::HMAC_SHA256_raw(hash_input_partial, sizeof(size_t)*2 + digest_len, digest);
                
                // Encrypt the payload
                byte_t *plaintext = (byte_t*) calloc(S1C_data_size, sizeof(byte_t));
                std::memcpy(plaintext, mm_value_iterator->c_str(), mm_value_iterator->length());
                ++mm_value_iterator;

                byte_t *emm_partial_ciphertext = (byte_t *) malloc(S1C_data_size + IV_len + S1C_emm_partial_index_len * sizeof(byte_t));
                AES::Encrypt(plaintext, S1C_data_size, enc_key, emm_partial_ciphertext);

                /* Add emm_full_index to the ciphertext in the end as a fingerprint */
                std::memcpy(emm_partial_ciphertext+S1C_data_size+IV_len, digest, fingerprint_len);
                

                /* Parse emm_partial_index_inner as an unsigned integer and store the emm_partial_ciphertext entry */
                std::memcpy(&emm_partial_index_inner_int, digest, sizeof(size_t));
                this->emm_partial_raw[emm_partial_index][emm_partial_index_inner_int] = emm_partial_ciphertext;

                free(plaintext);
            }
        }
    }

    std::cout << "Raw index built." << std::endl; 
}



/*
 * Finalise the setup of S1C by dumping emm_len_raw, emm_full_raw and emm_partial_raw into bloom filters
 * Outputs:
 *   1. emm_len: byte array of size 2 * (1 + epsilon) * N_KDP * (S1C_emm_len_XOR_key_len + S1C_emm_len_index_len)
 *   2. emm_raw: byte array of size 2 * (1 + epsilon) * ceil(N_KDP / page_size) * page_size
 *   3. emm_partial: byte array of size N_bins * 2 * (1 + epsilon) * bincap * (S1C_data_size + S1C_emm_partial_index_len)
 */
void Client::SetupFinalize() {
    // Build the Cuckoo hash table for emm_len
    size_t emm_len_size = std::ceil((1 + epsilon) * this->N_KDP);
    size_t emm_len_payload_len = sizeof(size_t) + S1C_emm_partial_index_len;
    this->emm_len = (byte_t *) malloc(2 * emm_len_size * emm_len_payload_len * sizeof(byte_t));
    randombytes(this->emm_len, 2 * emm_len_size * emm_len_payload_len);

    CuckooHasing::Build_hash_table(this->emm_len_raw, emm_len_payload_len, emm_len_size, this->emm_len, seed_emm_len);
    std::cout << "emm_len built." << std::endl; 

    // Build the Cuckoo hash table for emm_full
    size_t N_page_max = std::ceil(this->N_KDP / this->usable_slots);
    size_t emm_full_size = std::ceil((1 + epsilon) *  N_page_max);
    size_t emm_full_payload_len = page_size;
    this->emm_full = (byte_t *) malloc(2 * emm_full_size * emm_full_payload_len * sizeof(byte_t));
    randombytes(this->emm_full, 2 * emm_full_size * emm_full_payload_len);

    CuckooHasing::Build_hash_table(this->emm_full_raw, page_size, emm_full_size, this->emm_full, seed_emm_full);
    std::cout << "emm_full built." << std::endl; 

    // Build the Cuckoo hash table for emm_partial
    size_t emm_partial_size = std::ceil((1 + epsilon) * this->bincap);
    size_t emm_partial_payload_len = IV_len + S1C_data_size + S1C_emm_partial_index_len;
    this->emm_partial = (byte_t *) malloc(2 * this->N_bins * emm_partial_size * emm_partial_payload_len * sizeof(byte_t));
    randombytes(this->emm_partial, 2 * this->N_bins * emm_partial_size * emm_partial_payload_len);


    for (size_t bin_idx = 0; bin_idx < this->N_bins; bin_idx++) {
        size_t offset = 2 * bin_idx * emm_partial_size * emm_partial_payload_len;
        CuckooHasing::Build_hash_table(this->emm_partial_raw[bin_idx], emm_partial_payload_len, 
            emm_partial_size, this->emm_partial+offset, seed_emm_partial+2*bin_idx);

            if ((bin_idx+1) % std::max((size_t) 1, (this->N_bins / 10)) == 0)
                std::cout << "emm_partial: " << bin_idx+1 << "/" << this->N_bins << " built." << std::endl; 
    }
}


void Client::SetupFinalizeFullPages() {
    // Build the Cuckoo hash table for emm_len
    size_t emm_len_size = std::ceil((1 + epsilon) * this->N_KDP);
    size_t emm_len_payload_len = sizeof(size_t) + S1C_emm_partial_index_len;
    this->emm_len = (byte_t *) malloc(2 * emm_len_size * emm_len_payload_len * sizeof(byte_t));
    randombytes(this->emm_len, 2 * emm_len_size * emm_len_payload_len);

    CuckooHasing::Build_hash_table(this->emm_len_raw, emm_len_payload_len, emm_len_size, this->emm_len, seed_emm_len);
    std::cout << "emm_len built." << std::endl; 

    // Build the Cuckoo hash table for emm_full
    size_t N_page_max = std::ceil(this->N_KDP / this->usable_slots);
    size_t emm_full_size = std::ceil((1 + epsilon) *  N_page_max);
    size_t emm_full_payload_len = page_size;
    this->emm_full = (byte_t *) malloc(2 * emm_full_size * emm_full_payload_len * sizeof(byte_t));
    randombytes(this->emm_full, 2 * emm_full_size * emm_full_payload_len);

    CuckooHasing::Build_hash_table(this->emm_full_raw, page_size, emm_full_size, this->emm_full, seed_emm_full);
    std::cout << "emm_full built." << std::endl; 

    // Build the Cuckoo hash table for emm_partial
    size_t emm_partial_size = std::ceil((1 + epsilon) * this->bincap);
    size_t emm_partial_payload_len = IV_len + S1C_data_size + S1C_emm_partial_index_len;
    this->emm_partial = (byte_t *) malloc(2 * this->N_bins * emm_partial_size * emm_partial_payload_len * sizeof(byte_t));
    randombytes(this->emm_partial, 2 * this->N_bins * emm_partial_size * emm_partial_payload_len);
}


/*
 * Search token generation, also used in setup
 * Input:
 *   1. keyword: the search keyword
 * Outputs:
 *   1. emm_len_index (16 bytes): the index in emm_len that is used to store the query response volume for the keyword
 *   2. emm_len_XOR_key (4 bytes): the XOR key used to mask the query response volume
 *   3. hash_key (32 bytes): hash key used to compute the indices of the insertions (in emm_full and emm_partial)
 */
void Client::SearchTokenGen(std::string keyword, byte_t *emm_len_index, byte_t *emm_len_XOR_key, byte_t *token) {
    byte_t *hash_message = new byte_t[keyword.length()+1];
    byte_t digest[digest_len];

    // emm_len_index
    std::memcpy(hash_message, keyword.data(), keyword.length());
    hash_message[keyword.length()] = 0;
    Hash::HMAC_SHA256(hash_message, keyword.length()+1, this->PRF_key, digest);
    std::memcpy(emm_len_index, digest, S1C_emm_len_index_len);

    // emm_len_XOR_key
    hash_message[keyword.length()] = 1;
    Hash::HMAC_SHA256(hash_message, keyword.length()+1, this->PRF_key, digest);
    std::memcpy(emm_len_XOR_key, digest, S1C_emm_len_XOR_key_len);

    // hash_key
    hash_message[keyword.length()] = 2;
    Hash::HMAC_SHA256(hash_message, keyword.length()+1, this->PRF_key, digest);
    std::memcpy(token, digest, digest_len);

    free(hash_message);
}

/*
 * Process query response
 */
void Client::DecryptResponse(std::vector<byte_t*> *response_full, std::vector<byte_t*> *response_partial) {
    std::vector<std::string> results;
    for (byte_t * result: *response_full) {
        size_t page_usable_slots = (page_size - S1C_emm_full_index_len - IV_len) / S1C_data_size;
        byte_t *plaintext = (byte_t *) malloc(page_usable_slots * S1C_data_size * sizeof(byte_t));
        AES::Decrypt(result, page_usable_slots * S1C_data_size, enc_key, plaintext);

        for (size_t jj = 0; jj < page_usable_slots; jj++) {
            byte_t plaintext_slot[S1C_data_size];
            std::memcpy(plaintext_slot, plaintext+jj*S1C_data_size, S1C_data_size);

            std::string str((char *)plaintext_slot, sizeof(plaintext_slot));
            results.push_back(str);
            //std::cout << "Decrypted result (full): " << str << std::endl;
        }
    }

    for (byte_t * result: *response_partial) {
        byte_t *plaintext = (byte_t *) malloc(S1C_data_size * sizeof(byte_t));
        AES::Decrypt(result, S1C_data_size, enc_key, plaintext);
        std::string str((char *)plaintext, sizeof(plaintext));
        results.push_back(str);

        //std::cout << "Decrypted result (partial): " << str << std::endl;
    }
}



void Client::PrintMM() {
    for (const auto& pair : this->mmap_plaintext) {
        std::cout << pair.first << ": ";
        for (std::string val: pair.second)
            std::cout << val << ",";
        std::cout << std::endl;
    }
}



void Client::PrintMMStats() {
    std::cout << "# Keywords: " << this->N_keywords << std::endl;
    std::cout << "# KDP: " << this->N_KDP << std::endl;
}


byte_t *Client::getEncKey() {
    return this->enc_key;
}


std::unordered_map<std::string, std::vector<std::string>> *Client::getPlaintextMM() {
    return &(this->mmap_plaintext);
} 