#include <cmath>
#include <iostream>
#include <fstream>
#include <cstring>
#include <iterator>
#include <random>
#include <algorithm>

#include <openssl/err.h>

#include "Client.hpp"
#include "CuckooHashing.hpp"
#include "Utilities.hpp"
#include "randombytes.hpp"


/* Constructor */
Client::Client(DBType dbType, size_t N_KDP, size_t N_labels) {
    this->dbType = dbType;
    this->N_KDP = N_KDP;
    this->N_labels = N_labels;

    /* Compute the number of bins and bincap */
    this->usable_slots = (page_size - emm_index_len - IV_len) / data_size;

    this->bincap_full = (size_t) (bincap_const * logLogLambda * std::log(std::ceil(this->N_KDP / this->usable_slots)));
    this->N_bins_full = (size_t) std::ceil(std::ceil(this->N_KDP / this->usable_slots) / std::log(std::ceil(this->N_KDP / this->usable_slots)) / logLogLambda);

    if (dbType == SPARSEDB) {
        this->bincap_partial = (size_t) (bincap_const * logLogLambda * this->usable_slots * std::log(std::ceil(this->N_KDP / this->usable_slots)));
        this->N_bins_partial = std::ceil(N_KDP / logLogLambda / this->usable_slots / std::log(std::ceil(this->N_KDP / this->usable_slots)));
    }
    else {
        this->bincap_partial = this->usable_slots;
        this->N_bins_partial = N_labels;
    }
    

    this->seed_emm_full     = (size_t *) malloc(2 * this->N_bins_full * sizeof(size_t));
    this->seed_emm_partial  = (size_t *) malloc(2 * this->N_bins_partial * sizeof(size_t));

    std::cout << "Total pages: " << std::ceil(this->N_KDP / this->usable_slots) << std::endl;
    std::cout << "Usable slots per page: " << this->usable_slots << std::endl;
    std::cout << "Bincap full (raw): " << this->bincap_full << std::endl;
    std::cout << "N_bins full: " << this->N_bins_full << std::endl;
    std::cout << "Bincap partial (raw): " << this->bincap_partial << std::endl;
    std::cout << "N_bins partial: " << this->N_bins_partial << std::endl;
    std::cout << "---------------------" << std::endl;
}



/* 
 * Generate the keys for S1C
 * Keys include:
 *   1. 2* 256-bit PRF key used by HMAC-SHA256 to generate subkeys for each keyword.
 *   2. 2* 128-bit encryption key for the payloads 
 */
void Client::KeyGen(){
    randombytes(this->PRF_key_full, PRF_key_len);
    randombytes(this->enc_key_full, enc_key_len);

    randombytes(this->PRF_key_partial, PRF_key_len);
    randombytes(this->enc_key_partial, enc_key_len);

    randombytes(this->nonce, nonce_len);
}

/* 
 * Setup of D1C
 * No input required
 * Outputs the encrypted hash tables emm (stored in a contiguous byte_t array) and the seeds
 */
void Client::Setup() {
    /* Initialise emm_full */
    size_t emm_full_payload_len = page_size;
    size_t emm_full_bin_size = std::ceil((1+epsilon) * this->bincap_full);
    this->emm_full = (byte_t*) malloc(2 * this->N_bins_full * emm_full_bin_size * emm_full_payload_len * sizeof(byte_t));

    std::unordered_map<size_t, byte_t*> raw_table;
    for (size_t bin_idx = 0; bin_idx < this->N_bins_full; bin_idx++) {
        //std::cout << "Full page bins: " << bin_idx << std::endl;
        size_t offset = 2 * bin_idx * emm_full_payload_len * emm_full_bin_size;

        CuckooHasing::Build_hash_table_enc_and_fill(raw_table, emm_full_payload_len, emm_full_bin_size, this->emm_full+offset, 
                                            page_size-IV_len, this->seed_emm_full+2*bin_idx, this->enc_key_full);
    }

    /* Initialise emm_partial */
    size_t emm_partial_payload_len = 2*data_size + emm_index_len + IV_len;
    size_t emm_partial_bin_size = std::ceil((1+epsilon) * this->bincap_partial);
    this->emm_partial = (byte_t*) malloc(2 * this->N_bins_partial * emm_partial_bin_size * emm_partial_payload_len * sizeof(byte_t));
    for (size_t bin_idx = 0; bin_idx < this->N_bins_partial; bin_idx++) {
        //std::cout << "Partial bin: " << bin_idx << std::endl;
        size_t offset = 2 * bin_idx * emm_partial_payload_len * emm_partial_bin_size;

        CuckooHasing::Build_hash_table_enc_and_fill(raw_table, emm_partial_payload_len, emm_partial_bin_size, this->emm_partial+offset, 
                                            2*data_size+emm_index_len, this->seed_emm_partial+2*bin_idx, this->enc_key_partial);
    }
}



void Client::Setup_with_MM(std::unordered_map<std::string, std::vector<byte_t *>> *multimap, size_t N_rows_skip) {
    /* Build raw full page and partial multi-maps */
    std::unordered_map<size_t, std::unordered_map<size_t, byte_t*>> full_pages;
    std::unordered_map<size_t, std::unordered_map<size_t, byte_t*>> partial_bins;

    size_t counter = 0;
    for (auto kvp: (*multimap)) {
        counter ++;
        if (counter < N_rows_skip)
            continue;
        //if (counter > 1)
        //    continue;

        std::string keyword = kvp.first;

        size_t N_full_pages = kvp.second.size() / this->usable_slots;
        size_t N_remainder  = kvp.second.size() % this->usable_slots;
        this->keyword_counter_full[keyword] = N_full_pages;
        this->keyword_counter_partial[keyword] = N_remainder;

        /* Derive search token for full pages */
        byte_t *plaintext1 = (byte_t *) malloc(keyword.length() * sizeof(byte_t));
        byte_t *plaintext2 = (byte_t *) malloc(digest_len * sizeof(byte_t) + sizeof(size_t));
        byte_t digest[digest_len];
        byte_t token[emm_index_len];

        std::memcpy(plaintext1, keyword.c_str(), keyword.length());
        Hash::HMAC_SHA256(plaintext1, keyword.length(), this->PRF_key_full, plaintext2);

        /* Build full pages */
        for (size_t ii = 0; ii < N_full_pages; ii++) {
            std::memcpy(plaintext2+digest_len, &ii, sizeof(size_t));
            Hash::HMAC_SHA256(plaintext2, digest_len * sizeof(byte_t) + sizeof(size_t), this->PRF_key_full, digest);
            std::memcpy(token, digest, emm_index_len);

            size_t token_index = 0;
            std::memcpy(&token_index, token, sizeof(size_t));

            size_t bin_index = 0;
            Hash::HMAC_SHA256_raw(token, emm_index_len, digest);
            std::memcpy(&bin_index, digest, sizeof(size_t));
            bin_index = bin_index % this->N_bins_full;

            byte_t *payload = (byte_t *) calloc(page_size - IV_len, sizeof(byte_t));
            for (size_t jj = 0; jj < this->usable_slots; jj++)
                std::memcpy(payload+jj*data_size, kvp.second[ii*this->usable_slots+jj], data_size);
            std::memcpy(payload+this->usable_slots*data_size, token, emm_index_len);

            full_pages[bin_index][token_index] = payload;
        }

        /* Build the partial pages */
        size_t gamma_partial = 0;
        byte_t token_partial[emm_index_len];
        this->SearchTokenGenPartial(keyword, token_partial, &gamma_partial);

        byte_t hash_input[emm_index_len+sizeof(size_t)];
        std::memcpy(hash_input, token_partial, emm_index_len);

        size_t partial_index = 0;
        for (size_t ii = 0; ii < N_remainder; ii++) {
            std::memcpy(hash_input+emm_index_len, &ii, sizeof(size_t));
            Hash::HMAC_SHA256_raw(hash_input, emm_index_len+sizeof(size_t), digest);
            std::memcpy(&partial_index, digest, sizeof(size_t));
            
            byte_t *payload = (byte_t *) calloc(2*data_size+emm_index_len, sizeof(byte_t));
            std::memcpy(payload, keyword.c_str(), keyword.size());
            std::memcpy(payload+data_size, kvp.second[N_full_pages*this->usable_slots+ii], data_size);
            std::memcpy(payload+data_size*2, digest, emm_index_len);

            partial_bins[gamma_partial][partial_index] = payload;

            //std::cout << "Insertion partial index: " << partial_index << std::endl;
            //BIO_dump_fp(stdout, (const char *)digest, emm_index_len);
        }


        free(plaintext1);
        free(plaintext2);
    }

    std::cout << "Parsing done." << std::endl;

    /* Encrypt the full pages */
    size_t emm_full_payload_len = page_size;
    size_t emm_full_bin_size = std::ceil((1+epsilon) * this->bincap_full);
    this->emm_full = (byte_t*) malloc(2 * this->N_bins_full * emm_full_bin_size * emm_full_payload_len * sizeof(byte_t));

    for (size_t bin_idx = 0; bin_idx < this->N_bins_full; bin_idx++) {
        //std::cout << "Full page bins: " << bin_idx << std::endl;
        size_t offset = 2 * bin_idx * emm_full_payload_len * emm_full_bin_size;

        CuckooHasing::Build_hash_table_enc_and_fill(full_pages[bin_idx], emm_full_payload_len, emm_full_bin_size, this->emm_full+offset, 
                                            page_size-IV_len, this->seed_emm_full+2*bin_idx, this->enc_key_full);
        
        if (bin_idx % std::max((size_t) 1, this->N_bins_full / 10) == 0 )
            std::cout << "Encrypting full page bin: " << bin_idx << "/" << this->N_bins_full << std::endl;
    }


    /* Initialise emm_partial */
    size_t emm_partial_payload_len = 2*data_size + emm_index_len + IV_len;
    size_t emm_partial_bin_size = std::ceil((1+epsilon) * this->bincap_partial);
    this->emm_partial = (byte_t*) malloc(2 * this->N_bins_partial * emm_partial_bin_size * emm_partial_payload_len * sizeof(byte_t));
    for (size_t bin_idx = 0; bin_idx < this->N_bins_partial; bin_idx++) {
        //std::cout << "Partial bin: " << bin_idx << std::endl;
        size_t offset = 2 * bin_idx * emm_partial_payload_len * emm_partial_bin_size;

        CuckooHasing::Build_hash_table_enc_and_fill(partial_bins[bin_idx], emm_partial_payload_len, emm_partial_bin_size, this->emm_partial+offset, 
                                            2*data_size+emm_index_len, this->seed_emm_partial+2*bin_idx, this->enc_key_partial);

        if (bin_idx % std::max((size_t) 1, this->N_bins_partial / 10) == 0 )
            std::cout << "Encrypting partial bin: " << bin_idx << "/" << this->N_bins_partial << std::endl;
    }

    full_pages.clear();
    partial_bins.clear();
}


void Client::Setup_with_MM_fullpages(std::unordered_map<std::string, std::vector<byte_t *>> *multimap) {
    /* Build raw full page and partial multi-maps */
    std::unordered_map<size_t, std::unordered_map<size_t, byte_t*>> full_pages;


    for (auto kvp: (*multimap)) {
        std::string keyword = kvp.first;

        size_t N_full_pages = kvp.second.size() / this->usable_slots;
        size_t N_remainder  = kvp.second.size() % this->usable_slots;
        this->keyword_counter_full[keyword] = N_full_pages;
        this->keyword_counter_partial[keyword] = N_remainder;

        /* Derive search token for full pages */
        byte_t *plaintext1 = (byte_t *) malloc(keyword.length() * sizeof(byte_t));
        byte_t *plaintext2 = (byte_t *) malloc(digest_len * sizeof(byte_t) + sizeof(size_t));
        byte_t digest[digest_len];
        byte_t token[emm_index_len];

        std::memcpy(plaintext1, keyword.c_str(), keyword.length());
        Hash::HMAC_SHA256(plaintext1, keyword.length(), this->PRF_key_full, plaintext2);

        /* Build full pages */
        for (size_t ii = 0; ii < N_full_pages; ii++) {
            std::memcpy(plaintext2+digest_len, &ii, sizeof(size_t));
            Hash::HMAC_SHA256(plaintext2, digest_len * sizeof(byte_t) + sizeof(size_t), this->PRF_key_full, digest);
            std::memcpy(token, digest, emm_index_len);

            size_t token_index = 0;
            std::memcpy(&token_index, token, sizeof(size_t));

            size_t bin_index = 0;
            Hash::HMAC_SHA256_raw(token, emm_index_len, digest);
            std::memcpy(&bin_index, digest, sizeof(size_t));
            bin_index = bin_index % this->N_bins_full;

            byte_t *payload = (byte_t *) calloc(page_size - IV_len, sizeof(byte_t));
            for (size_t jj = 0; jj < this->usable_slots; jj++)
                std::memcpy(payload+jj*data_size, kvp.second[ii*this->usable_slots+jj], data_size);
            std::memcpy(payload+this->usable_slots*data_size, token, emm_index_len);

            full_pages[bin_index][token_index] = payload;
        }

        free(plaintext1);
        free(plaintext2);
    }

    std::cout << "Parsing done." << std::endl;

    /* Encrypt the full pages */
    size_t emm_full_payload_len = page_size;
    size_t emm_full_bin_size = std::ceil((1+epsilon) * this->bincap_full);
    this->emm_full = (byte_t*) malloc(2 * this->N_bins_full * emm_full_bin_size * emm_full_payload_len * sizeof(byte_t));

    for (size_t bin_idx = 0; bin_idx < this->N_bins_full; bin_idx++) {
        //std::cout << "Full page bins: " << bin_idx << std::endl;
        size_t offset = 2 * bin_idx * emm_full_payload_len * emm_full_bin_size;

        CuckooHasing::Build_hash_table_enc_and_fill(full_pages[bin_idx], emm_full_payload_len, emm_full_bin_size, this->emm_full+offset, 
                                            page_size-IV_len, this->seed_emm_full+2*bin_idx, this->enc_key_full);
        
        if (bin_idx % std::max((size_t) 1, this->N_bins_full / 10) == 0 )
            std::cout << "Encrypting full page bin: " << bin_idx << "/" << this->N_bins_full << std::endl;
    }


    /* Initialise emm_partial */
    size_t emm_partial_payload_len = 2*data_size + emm_index_len + IV_len;
    size_t emm_partial_bin_size = std::ceil((1+epsilon) * this->bincap_partial);
    this->emm_partial = (byte_t*) malloc(2 * this->N_bins_partial * emm_partial_bin_size * emm_partial_payload_len * sizeof(byte_t));

    full_pages.clear();   
}



/*
 * Search token generation for Dummy1C
 * Input:
 *   1. keyword: the search keyword
 * Outputs:
 *   1. A vector of tokens (32-byte each)
 */
void Client::SearchTokenGenDummy1C(std::string keyword, std::vector<byte_t *> *tokens) {
    /* Check if the keyword exists */
    if (this->keyword_counter_full.count(keyword) == 0) {
        return;
    }

    /* Derive search token */
    byte_t *plaintext1 = (byte_t *) malloc(keyword.length() * sizeof(byte_t));
    byte_t *plaintext2 = (byte_t *) malloc(digest_len * sizeof(byte_t) + sizeof(size_t));

    std::memcpy(plaintext1, keyword.c_str(), keyword.length());
    
    Hash::HMAC_SHA256(plaintext1, keyword.length(), this->PRF_key_full, plaintext2);
    for (size_t ii = 0; ii < this->keyword_counter_full[keyword]; ii++) {
        byte_t digest [digest_len];
        byte_t *token = (byte_t *) malloc(emm_index_len * sizeof(byte_t));

        std::memcpy(plaintext2+digest_len, &ii, sizeof(size_t));
        Hash::HMAC_SHA256(plaintext2, digest_len * sizeof(byte_t) + sizeof(size_t), this->PRF_key_full, digest);
        std::memcpy(token, digest, emm_index_len);
        tokens->push_back(token);
    }

    free(plaintext1);
    free(plaintext2);
}


/*
 * Decrypt query response
 * The query response contains keyword_counter[keyword] entries but each entry has two payloads (due to the use of Cuckoo hashing)
 * The client has to use the tokens to filter the query response
 */
void Client::DecryptSearchResponseDummy1C(std::vector<byte_t *> *tokens, std::vector<byte_t *> *responses) {

    std::vector<byte_t *>::const_iterator responses_iter = responses->begin();
    for (byte_t *token: *tokens) {
        byte_t *ciphertext = *responses_iter;
        ++responses_iter;

        byte_t *plaintext_bytes = (byte_t *) malloc((page_size - IV_len) * sizeof(byte_t));
        AES::Decrypt(ciphertext, page_size - IV_len, this->enc_key_full, plaintext_bytes);

        //BIO_dump_fp(stdout, (const char *)plaintext_bytes, 48);

        bool check = true;
        for (int ii = 0; ii < emm_index_len; ii++)
            if (plaintext_bytes[page_size - emm_index_len - IV_len + ii] != token[ii])
                check = false;

        if (check == true) {
            check = true;
            std::string plaintext((char *)plaintext_bytes, page_size - emm_index_len - IV_len);
            //std::cout << "Plaintext 1: " << plaintext << std::endl;
            //plaintexts.push_back(plaintext);
            //operations.push_back(plaintext_bytes[Dummy1C_data_size]);
        } else {
            AES::Decrypt(ciphertext+page_size, page_size - IV_len, this->enc_key_full, plaintext_bytes);
            std::string plaintext((char *)plaintext_bytes, page_size - emm_index_len - IV_len);
            //std::cout << "Plaintext 2: " << plaintext << std::endl;
            //plaintexts.push_back(plaintext);
            //operations.push_back(plaintext_bytes[Dummy1C_data_size]);
        }
    }
}


/*
 * Search token generation for partial emm
 * Input:
 *   1. keyword: the search keyword
 * Outputs:
 *   1. A tokens (32-byte)
 *   2. A counter that records the number of leftover elements in emm_partial to be retrieved
 *   3. The bin index gamma_partial where the partial indices are stored in 
 */
void Client::SearchTokenGenPartial(std::string keyword, byte_t *token, size_t *gamma_partial) {
    byte_t *plaintext = (byte_t*) malloc(keyword.length() * sizeof(byte_t));
    byte_t digest1[digest_len];
    byte_t digest2[digest_len];

    /* Generate gamma_partial */
    if (this->dbType == SPARSEDB) {
        std::memcpy(plaintext, keyword.c_str(), keyword.length());
        Hash::HMAC_SHA256(plaintext, keyword.length(), this->PRF_key_partial, digest1);
        Hash::HMAC_SHA256_raw(digest1, digest_len, digest2);

        std::memcpy(gamma_partial, digest2, sizeof(size_t));
        (*gamma_partial) = (*gamma_partial) % this->N_bins_partial;
    }
    else {
        /* Generate a random choice of bin index if it does not exist */
        if (this->bin_ids_1C.count(keyword) == 0){
            size_t bin_id = rand() % this->N_bins_partial;
            this->bin_ids_1C[keyword] = bin_id;
        }
        (*gamma_partial) = this->bin_ids_1C[keyword];
        
    }

    /* Generate search token */
    byte_t nonce_current[nonce_len];
    std::memcpy(nonce_current, this->nonce, nonce_len);

    if ((*gamma_partial) < this->counter_flush) {
        size_t nonce_counter = 0;
        std::memcpy(&nonce_counter, nonce_current, sizeof(size_t));
        nonce_counter += 1;
        std::memcpy(nonce_current, &nonce_counter, sizeof(size_t));
    }

    byte_t *plaintext2 = (byte_t *) malloc(digest_len * sizeof(byte_t) + keyword.length() * sizeof(byte_t));
    Hash::HMAC_SHA256(nonce_current, nonce_len, this->PRF_key_partial, plaintext2);
    std::memcpy(plaintext2+digest_len, keyword.c_str(), keyword.length());
    Hash::HMAC_SHA256(plaintext2, digest_len+keyword.length(), this->PRF_key_partial, digest1);
    std::memcpy(token, digest1, emm_index_len);
}


/*
 * Search for the keyword in the client state 
 */
void Client::SearchQueryStash(std::string keyword) {
    size_t counter = 0;
    /* stash_partial_new */
    for (auto stash: this->stash_partial_new)
        for (auto entry: stash.second)
            if (std::get<0>(entry) == keyword)
                counter += 1;

    /* stash_partial_out */
    for (auto stash: this->stash_partial_out)
        for (auto entry: stash.second)
            if (std::get<0>(entry) == keyword)
                counter += 1;

    /* stash_full_new */
    for (auto entry: this->stash_full_new) 
        if (std::get<0>(entry) == keyword)
            counter += 1;

    /* stash_full_out */
    for (auto stash: this->stash_full_out) 
        if (std::get<0>(stash.second) == keyword)
            counter += 1;
}


/*
 * Decrypt query response from partial emm
 * The client has to use the tokens to filter the query response
 */
void Client::DecryptSearchResponsePartial(byte_t *token, std::vector<byte_t *> *responses) {
    size_t idx = 0;
    byte_t hash_input[emm_index_len+sizeof(size_t)];
    byte_t digest[digest_len];
    std::memcpy(hash_input, token, emm_index_len);

    for (byte_t *response: *responses) {
        byte_t *plaintext_bytes = (byte_t *) malloc((2*data_size + emm_index_len) * sizeof(byte_t));
        AES::Decrypt(response, 2*data_size + emm_index_len, this->enc_key_partial, plaintext_bytes);

        std::memcpy(hash_input+emm_index_len, &idx, sizeof(size_t));
        Hash::HMAC_SHA256_raw(hash_input, emm_index_len+sizeof(size_t), digest);
        //BIO_dump_fp(stdout, (const char *)plaintext_bytes, 48);

        bool check = true;
        for (int ii = 0; ii < emm_index_len; ii++)
            if (plaintext_bytes[2*data_size + ii] != digest[ii])
                check = false;

        if (check == true) {
            check = true;
            std::string plaintext((char *)plaintext_bytes+data_size, data_size);
            //std::cout << "Plaintext 1: " << plaintext << std::endl;
            //plaintexts.push_back(plaintext);
            //operations.push_back(plaintext_bytes[Dummy1C_data_size]);
        } else {
            AES::Decrypt(response+(2*data_size + emm_index_len + IV_len), 2*data_size + emm_index_len, this->enc_key_partial, plaintext_bytes);
            std::string plaintext((char *)plaintext_bytes+data_size, data_size);
            //std::cout << "Plaintext 2: " << plaintext << std::endl;
            //plaintexts.push_back(plaintext);
            //operations.push_back(plaintext_bytes[Dummy1C_data_size]);
        }
        idx++;
    }
}


/*
 * Run the first part of an update query:
 *   1. Add the label-value pair to stash_partial_new
 *   2. If counter_flush == N_labels:
 *     - Update the nonce
 *     - Dump stash_partial_new to stash_partial_out
 *     - Dump stash_full_new to stash_full_out
 */
void Client::UpdateInitialize(std::string keyword, byte_t *value) {
    this->counter_flush += 1;

    /* Generate gamma */
    byte_t *plaintext = (byte_t*) malloc(keyword.length() * sizeof(byte_t));
    byte_t digest1[digest_len];
    byte_t digest2[digest_len];
    size_t gamma = 0;

    if (dbType == SPARSEDB) {
        std::memcpy(plaintext, keyword.c_str(), keyword.length());
        Hash::HMAC_SHA256(plaintext, keyword.length(), this->PRF_key_partial, digest1);
        Hash::HMAC_SHA256_raw(digest1, digest_len, digest2);

        std::memcpy(&gamma, digest2, sizeof(size_t));
        gamma = gamma % this->N_bins_partial;
    }
    else {
        /* Generate a random choice of bin index */
        if (this->bin_ids_1C.count(keyword) == 0){
            size_t bin_id = rand() % this->N_bins_partial;
            this->bin_ids_1C[keyword] = bin_id;
        }
        gamma = bin_ids_1C[keyword];
        
    }
    
    /* Add label-value pair to stash_partial_new */
    if (this->stash_partial_new.count(gamma) == 0) {
        std::vector<std::tuple<std::string, byte_t*>> v;
        std::tuple<std::string, byte_t*> newKVP(keyword, value);
        v.push_back(newKVP);
        this->stash_partial_new[gamma] = v;
    }
    else {
        std::tuple<std::string, byte_t*> newKVP(keyword, value);
        this->stash_partial_new[gamma].push_back(newKVP);
    }

    /*
    std::cout << "Stash_partial_new" << std::endl;
    for  (auto entry: this->stash_partial_new) {
        std::cout << "Index: " << entry.first << std::endl;
        for (auto kvp: entry.second) {
            std::string val(std::get<1>(kvp), std::get<1>(kvp)+16);
            std::cout << std::get<0>(kvp) << "," << val << std::endl;
        }
        std::cout << "-------------------" << std::endl;
    }
    */

    /* Update the client stash if counter_flush == N_labels */
    if (this->counter_flush == this->N_bins_partial) {
        /* Increment the nonce */
        size_t nonce_counter = 0;
        std::memcpy(&nonce_counter, this->nonce, sizeof(size_t));
        nonce_counter += 1;
        std::memcpy(this->nonce, &nonce_counter, sizeof(size_t));

        /* Flush stash_partial_new to stash_partial_out and reset stash_partial_new */
        this->stash_partial_out = this->stash_partial_new;
        std::unordered_map<size_t, std::vector<std::tuple<std::string, byte_t *>>> newMap;
        this->stash_partial_new = newMap;

        /* Generate a random sequence pi(j) */
        std::vector<size_t> perm_vec;
        for (size_t idx = 0; idx < this->N_bins_partial; idx++)
            perm_vec.push_back(idx);

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(perm_vec.begin(), perm_vec.end(), g);

        /* Flush stash_full_new to stash_full_out and reset stash_full_new */
        std::unordered_map<size_t, std::tuple<std::string, byte_t *>> newStashOut;
        this->stash_full_out = newStashOut;

        for (auto key_values_pair: this->stash_full_new) {
            size_t idx = perm_vec.back();
            perm_vec.pop_back();
            this->stash_full_out[idx] = key_values_pair;

            //std::cout << "Stash out keyword: " << std::get<0>(key_values_pair) << std::endl;
        }

        std::vector<std::tuple<std::string, byte_t *>> newStashNew;
        this->stash_full_new = newStashNew;
        this->counter_flush = 0;

        /*
        std::cout << "Stash_full_out" << std::endl;
        for  (auto entry: this->stash_full_out) {
            std::cout << "Index: " << std::get<0>(entry) << std::endl;
        }
        std::cout << "-------------------" << std::endl;
        */
    }

    /*
    std::cout << "Stash_partial_out" << std::endl;
    for  (auto entry: this->stash_partial_out) {
        std::cout << "Index: " << entry.first << std::endl;
        for (auto kvp: entry.second) {
            std::string val(std::get<1>(kvp), std::get<1>(kvp)+16);
            std::cout << std::get<0>(kvp) << "," << val << std::endl;
        }
        std::cout << "-------------------" << std::endl;
    }
    */
}


/*
 * Run the second part of an update query:
 *   1. Get the label-payload pair for the current update
 *   2. Generate the gamma for the current update
 */
size_t Client::UpdateGammaGen(byte_t *token) {
    //std::cout << "counter_flush:" << this->counter_flush << std::endl;

    /* If stash_full_out[counter_flush] is empty, generate a random gamma */
    if (this->stash_full_out.count(this->counter_flush) == 0) {
        this->queryTypeFull = DUMMY;
        return this->RandomGammaGenDummy1C();
    }

    /* Else, generate gamma based on the keyword */
    this->queryTypeFull = REAL;
    return this->UpdateGammaGenDummy1C(std::get<0>(this->stash_full_out[this->counter_flush]), token);
}


/* 
 * Generate a real gamma for the keyword
 */
size_t Client::UpdateGammaGenDummy1C(std::string keyword, byte_t *token) {
    /* Get the keyword counter */
    size_t counter = 0;
    if (this->keyword_counter_full.count(keyword) != 0)
        counter = this->keyword_counter_full[keyword];
    this->keyword_counter_full[keyword] = counter + 1;
    
    /* Derive the search token for the update */
    byte_t *plaintext1 = (byte_t *) malloc(keyword.length() * sizeof(byte_t));
    byte_t *plaintext2 = (byte_t *) malloc(digest_len * sizeof(byte_t) + sizeof(size_t));
    byte_t digest[digest_len];

    std::memcpy(plaintext1, keyword.c_str(), keyword.length());
    Hash::HMAC_SHA256(plaintext1, keyword.length(), this->PRF_key_full, plaintext2);
    std::memcpy(plaintext2+digest_len, &counter, sizeof(size_t));
    Hash::HMAC_SHA256(plaintext2, digest_len * sizeof(byte_t) + sizeof(size_t), this->PRF_key_full, digest);
    std::memcpy(token, digest, emm_index_len);

    Hash::HMAC_SHA256_raw(token, emm_index_len, digest);
    size_t gamma = 0;
    std::memcpy(&gamma, digest, sizeof(size_t));
    gamma = gamma % this->N_bins_full;

    return gamma;
}


/*
 * Decrypt hash table into an unordered map
 * Removes encryptions of zero 
 * hash table entry: payload + index (+ IV)
 * mm_bin format:
 *   - key: index
 *   - value: payload + index
 */
void Client::DecryptHashTableDummy1C(byte_t *hash_table, int plaintext_len, int block_len, size_t hash_table_size, std::unordered_map<size_t, byte_t*> *mm_bin) {
    for (size_t idx = 0; idx < 2*hash_table_size; idx++) {
        /* Decrypt one entry */
        size_t offset = block_len*idx;
        byte_t* plaintext = (byte_t *) malloc(plaintext_len * sizeof(byte_t));
        AES::Decrypt(hash_table+offset, plaintext_len, this->enc_key_full, plaintext);

        /* Check if the entry is a dummy one*/
        bool dummy = true;
        for (int ii = 0; ii < plaintext_len; ii++) {
            if (plaintext[ii] != 0) {
                dummy = false;
                break;
            }
        }

        /* Insert the entry into mm_bin if it is a real entry */
        if (dummy == false) {
            size_t mm_bin_index = 0;
            std::memcpy(&mm_bin_index, plaintext+(plaintext_len-emm_index_len), sizeof(size_t));
            (*mm_bin)[mm_bin_index] = plaintext;
        }
    }
}


/*
 * Decrypt hash table into an unordered map
 * Removes encryptions of zero 
 * hash table entry: label (data_size bytes) + value (data_size bytes) + index (emm_index_len) (+ IV)
 * index is ignored during decryption
 * mm_bin format:
 *   - key: label (converted to string)
 *   - value: value
 */
void Client::DecryptHashTablePartial(byte_t *hash_table, int block_len, size_t hash_table_size, std::unordered_map<std::string, std::vector<byte_t*>> *mm_ctr) {
    for (size_t idx = 0; idx < 2*hash_table_size; idx++) {
        /* Decrypt one entry */
        size_t offset = block_len*idx;
        byte_t *plaintext = (byte_t *) malloc((2 * data_size + emm_index_len) * sizeof(byte_t));
        AES::Decrypt(hash_table+offset, data_size*2+emm_index_len, this->enc_key_partial, plaintext);

        //BIO_dump_fp (stdout, (const char *)plaintext, 2 * data_size+emm_index_len);

        /* Check if the entry is a dummy one*/
        bool dummy = true;
        for (int ii = 0; ii < data_size*2; ii++) {
            if (plaintext[ii] != 0) {
                dummy = false;
                break;
            }
        }

        /* Insert the entry into mm_bin if it is a real entry */
        if (dummy == false) {
            //BIO_dump_fp (stdout, (const char *)plaintext, 2 * data_size+emm_index_len);

            std::string label((char *)plaintext, data_size);
            if ((*mm_ctr).count(label) == 0) {
                std::vector<byte_t*> values;
                (*mm_ctr)[label] = values;
            }
            /* CHECK IF THIS WORKS */
            (*mm_ctr)[label].push_back(plaintext+data_size);
        }
    }
}


/* 
 * Insert the new entry into the decrypted multimap
 */
void Client::UpdateMMBinDummy1C(byte_t *token, std::unordered_map<size_t, byte_t*> *mm_bin) {
    /* Load up the plaintext */
    byte_t *plaintext = (byte_t *) malloc((page_size - IV_len) * sizeof(byte_t));
    std::memcpy(plaintext, std::get<1>(this->stash_full_out[this->counter_flush]), page_size - emm_index_len - IV_len);
    std::memcpy(plaintext+(page_size - emm_index_len - IV_len), token, emm_index_len);

    /* Convert token into size_t */
    size_t index = 0;
    std::memcpy(&index, token, sizeof(size_t));
    (*mm_bin)[index] = plaintext;
}



/* 
 * Re-encrypt the multimap
 */
void Client::ReencryptMMDummy1C(std::unordered_map<size_t, byte_t*> mm_bin, byte_t *hash_table, size_t *seeds) {
    size_t emm_payload_len = page_size;
    size_t emm_bin_size = std::ceil((1+epsilon) * this->bincap_full);

    CuckooHasing::Build_hash_table_enc_and_fill(mm_bin, emm_payload_len, emm_bin_size, hash_table, 
                                                page_size - IV_len, seeds, this->enc_key_full);
}


/* 
 * Generate a random gamma for the keyword
 */
size_t Client::RandomGammaGenDummy1C() {
    byte_t digest[digest_len];
    RAND_bytes(digest, digest_len);

    size_t gamma = 0;
    std::memcpy(&gamma, digest, sizeof(size_t));
    gamma = gamma % this->N_bins_full;

    return gamma;

}



/*
 * Run the final part of an update query:
 *   1. Decrypt a bin and reparse it as label-value pairs
 *   2. Add entries in stash_partial_out to the label-value pairs and empty stash_partial_out
 *   3. Fill new full pages (flush to stash_full_new) and partial emms (re-encrypt and overwrite the old bin)
 */
void Client::UpdateFinalize(byte_t *response, byte_t *hash_table) {
    /* Decrypt the content of the bin */
    size_t emm_partial_payload_len = 2*data_size + emm_index_len + IV_len;
    size_t emm_partial_bin_size = std::ceil((1+epsilon) * this->bincap_partial);
    std::unordered_map<std::string, std::vector<byte_t*>> mm_ctr;
    this->DecryptHashTablePartial(response, emm_partial_payload_len, emm_partial_bin_size, &mm_ctr);

    /* Add entries from stash_partial_out to mm_ctr and empty stash_partial_out[counter_flush] */
    //std::cout << "mm_ctr size: " << mm_ctr.size() << std::endl;
    //std::cout << "Stash partial size: " << this->stash_partial_out[this->counter_flush].size() << std::endl;

    for (auto kvp: this->stash_partial_out[this->counter_flush]) {
        std::string keyword = std::get<0>(kvp);
        if (mm_ctr.count(keyword) == 0) {
            std::vector<byte_t*> values;
            mm_ctr[keyword] = values;
        }
        mm_ctr[keyword].push_back(std::get<1>(kvp));
    }
    std::vector<std::tuple<std::string, byte_t *>> newVec;
    this->stash_partial_out[this->counter_flush] = newVec;

    /* 
     * Move full pages to stash_full_new
     * Dump the others to a raw table (and encrypt later)
     */
    std::unordered_map<size_t, byte_t*> partial_table_raw;
    for (auto key_values_pair: mm_ctr) {
        size_t values_count =  key_values_pair.second.size();
        size_t full_page_count = values_count / this->usable_slots;

        std::vector<byte_t *> values_all = key_values_pair.second;

        //std::cout << "Keyword: " << key_values_pair.first << std::endl;
        //std::cout << "#Value: " << key_values_pair.second.size() << std::endl;

        /* Process full pages*/
        for (size_t full_page_idx = 0; full_page_idx < full_page_count; full_page_idx++) {
            byte_t *values_full_page = (byte_t *) malloc((page_size - IV_len) * sizeof(byte_t));

            /* Batch values together */
            for (unsigned int payload_idx = 0; payload_idx < this->usable_slots; payload_idx++) {
                byte_t * payload = values_all.back();
                values_all.pop_back();
                std::memcpy(values_full_page+data_size*payload_idx, payload, data_size);
            }
            std::tuple<std::string, byte_t*> entry(key_values_pair.first, values_full_page);
            this->stash_full_new.push_back(entry);
        }

        /* Generate the search token F(nonce_new, label) */
        byte_t nonce_new[nonce_len];
        std::memcpy(nonce_new, this->nonce, nonce_len);
        size_t nonce_counter = 0;
        std::memcpy(&nonce_counter, nonce_new, sizeof(size_t));
        nonce_counter += 1;
        std::memcpy(nonce_new, &nonce_counter, sizeof(size_t));

        byte_t *plaintext = (byte_t *) malloc(digest_len * sizeof(byte_t) + key_values_pair.first.length() * sizeof(byte_t));
        byte_t token_keyword[digest_len];

        Hash::HMAC_SHA256(nonce_new, nonce_len, this->PRF_key_partial, plaintext);
        std::memcpy(plaintext+digest_len, key_values_pair.first.c_str(), key_values_pair.first.length());
        Hash::HMAC_SHA256(plaintext, digest_len+key_values_pair.first.length(), this->PRF_key_partial, token_keyword);

        byte_t token_partial[digest_len + sizeof(size_t)];
        std::memcpy(token_partial, token_keyword, digest_len);

        /* Processing partial values */
        size_t counter_partial = 0;
        byte_t digest[digest_len];
        size_t partial_index = 0;
        while (values_all.empty() == false) {
            /* Derive index */
            std::memcpy(token_partial+digest_len, &counter_partial, sizeof(size_t));
            Hash::HMAC_SHA256_raw(token_partial, digest_len+sizeof(size_t), digest);
            counter_partial++;

            /* Prepare index and the payload */
            std::memcpy(&partial_index, digest, sizeof(size_t));

            byte_t *payload = (byte_t *) malloc((2*data_size+emm_index_len) * sizeof(byte_t));
            for (int idx = 0; idx < 2*data_size+emm_index_len; idx++)
                payload[idx] = 0;

            std::memcpy(payload, key_values_pair.first.c_str(), key_values_pair.first.length());
            std::memcpy(payload+data_size, values_all.back(), data_size);
            values_all.pop_back();
            std::memcpy(payload+2*data_size, digest, emm_index_len);

            partial_table_raw[partial_index] = payload;
        }
        /* Update keyword counter */
        this->keyword_counter_partial[key_values_pair.first] = counter_partial;
    }
    CuckooHasing::Build_hash_table_enc_and_fill(partial_table_raw, emm_partial_payload_len, emm_partial_bin_size, hash_table, 
                                                2*data_size+emm_index_len, this->seed_emm_partial+2*this->counter_flush, this->enc_key_partial);

    /*
    std::cout << "Stash_full_new" << std::endl;
    for  (auto entry: this->stash_full_new) {
        std::cout << "Keyword: " << std::get<0>(entry) << std::endl;
    }
    std::cout << "-------------------" << std::endl;
    */
}




