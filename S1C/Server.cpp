#include <cmath>
#include <iostream>
#include <fstream>
#include <cstring>
#include <iterator>

#include <openssl/err.h>

#include "Server.hpp"
#include "CuckooHashing.hpp"
#include "Utilities.hpp"

#include "AES.hpp"



/* Constructor */
Server::Server(std::string folder_emm_client, bool in_memory_client) {
    this->folder_emm = folder_emm_client;
    this->in_memory = in_memory_client;
}

/* Store emm_len */
void Server::Store_emm_len(byte_t *emm_len_client) {
    if (this->in_memory) {
        this->emm_len = emm_len_client;
    }
    else {
        std::ofstream outputFile(this->folder_emm + "emm_len.bin", std::ofstream::binary | std::ofstream::out);
        if (!outputFile.is_open())
            return;
        outputFile.write(reinterpret_cast<const char*>(emm_len_client), 2*this->emm_len_payload_len*this->emm_len_size);
        outputFile.close();
    }
}


/* Store emm_full */
void Server::Store_emm_full(byte_t *emm_full_client) {
    if (this->in_memory) {
        this->emm_full = emm_full_client;
    }
    else {
        std::ofstream outputFile(this->folder_emm + "emm_full.bin", std::ofstream::binary | std::ofstream::out);
        if (!outputFile.is_open())
            return;
        outputFile.write(reinterpret_cast<const char*>(emm_full_client), 2*this->emm_full_payload_len*this->emm_full_size);
        outputFile.close();
    }
}


/* Store emm_partial */
void Server::Store_emm_partial(byte_t *emm_partial_client) {
    if (this->in_memory) {
        this->emm_partial = emm_partial_client;
    }
    else {
        std::ofstream outputFile(this->folder_emm + "emm_partial.bin", std::ofstream::binary | std::ofstream::out);
        if (!outputFile.is_open())
            return;
        outputFile.write(reinterpret_cast<const char*>(emm_partial_client), 2*this->N_bins*this->emm_partial_payload_len*this->emm_partial_size);
        outputFile.close();
    }
}

/* Store information about the emm */
void Server::Store_emm_info(unsigned int emm_len_payload_len, size_t emm_len_size, unsigned int emm_full_payload_len, 
                            size_t emm_full_size, unsigned int emm_partial_payload_len, size_t N_bins, size_t emm_partial_size) {
        this->emm_len_payload_len       = emm_len_payload_len;
        this->emm_len_size              = emm_len_size;
        this->emm_full_payload_len      = emm_full_payload_len;
        this->emm_full_size             = emm_full_size;
        this->emm_partial_payload_len   = emm_partial_payload_len;
        this->N_bins                    = N_bins;
        this->emm_partial_size          = emm_partial_size;

        this->usable_slots = (page_size - S1C_emm_full_index_len - IV_len) / S1C_data_size;

    }


/* Store seeds */
void Server::Store_seeds(size_t *seed_emm_len_client, size_t *seed_emm_full_client, size_t *seed_emm_partial_client) {
    this->seed_emm_len = seed_emm_len_client;
    this->seed_emm_full = seed_emm_full_client;
    this->seed_emm_partial = seed_emm_partial_client;
}

/* Run the query. Put the full pages in response_full, put the partial responses in response_partial*/
void Server::ExecuteQuery(byte_t *emm_len_index, byte_t *emm_len_XOR_key, byte_t *token,
    std::vector<byte_t*> *response_full, std::vector<byte_t*> *response_partial) {

    /* Get query response volume */
    size_t emm_len_index_int = 0;
    std::memcpy(&emm_len_index_int, emm_len_index, sizeof(size_t));
    size_t pos1 = emm_len_index_int * this->seed_emm_len[0] % this->emm_len_size;
    size_t pos2 = emm_len_index_int * this->seed_emm_len[1] % this->emm_len_size;

    byte_t *emm_len_payload = (byte_t *) malloc(this->emm_len_payload_len * sizeof(byte_t));
    if (this->in_memory == true)
        CuckooHasing::Lookup(this->emm_len, this->emm_len_payload_len, this->emm_len_size, pos1, pos2, emm_len_index, emm_len_payload);
    else
        CuckooHasing::LookupSSD(this->folder_emm + "emm_len.bin", this->emm_len_payload_len, this->emm_len_size, pos1, pos2, emm_len_index, emm_len_payload);

    for (int ii = 0; ii < S1C_emm_len_XOR_key_len; ii++)
        emm_len_payload[ii] ^= emm_len_XOR_key[ii];

    size_t val_len = 0;
    std::memcpy(&val_len, emm_len_payload, sizeof(size_t));

    /* Calculate where to retrieve the documents */
    
    size_t N_full_pages = val_len / this->usable_slots;
    size_t remainder = val_len - N_full_pages * this->usable_slots;

    /* Retrieve documents from emm_full */
    byte_t hash_input_pages[sizeof(size_t) + digest_len];
    size_t emm_full_page_index_int = 0;
    byte_t digest[digest_len];

    std::memcpy(hash_input_pages+sizeof(size_t), token, digest_len);

    for (size_t jj = 0; jj < N_full_pages; jj++) {
        /* Compute the emm key for the jj-th page */
        std::memcpy(hash_input_pages, &jj, sizeof(size_t));
        Hash::HMAC_SHA256_raw(hash_input_pages, sizeof(size_t) + digest_len, digest);

        std::memcpy(&emm_full_page_index_int, digest, sizeof(size_t));

        pos1 = emm_full_page_index_int * this->seed_emm_full[0] % this->emm_full_size;
        pos2 = emm_full_page_index_int * this->seed_emm_full[1] % this->emm_full_size;

        byte_t *emm_full_payload = (byte_t *) malloc(this->emm_full_payload_len * sizeof(byte_t));
        if (this->in_memory == true)
            CuckooHasing::Lookup(this->emm_full, this->emm_full_payload_len, this->emm_full_size, pos1, pos2, digest, emm_full_payload);
        else
            CuckooHasing::LookupSSD(this->folder_emm + "emm_full.bin", this->emm_full_payload_len, this->emm_full_size, pos1, pos2, digest, emm_full_payload);

        (*response_full).push_back(emm_full_payload);
    }

    
    /* Retrieve documents from emm_partial */
    // Get the last "page index"
    N_full_pages += 1;
    std::memcpy(hash_input_pages, &N_full_pages, sizeof(size_t));
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
    size_t offset =  2 * emm_partial_index * this->emm_partial_size * emm_partial_payload_len;
    size_t seed1 = this->seed_emm_partial[2*emm_partial_index];
    size_t seed2 = this->seed_emm_partial[2*emm_partial_index+1];

    std::memcpy(hash_input_partial, &N_full_pages, sizeof(size_t));
    std::memcpy(hash_input_partial+2*sizeof(size_t), token, digest_len);

    for (size_t jj = 0; jj < remainder; jj++) {
        // Get the index in the emm_partial_raw[emm_partial_index]
        std::memcpy(hash_input_partial+sizeof(size_t), &jj, sizeof(size_t));
        Hash::HMAC_SHA256_raw(hash_input_partial, sizeof(size_t)*2 + digest_len, digest);
        
        std::memcpy(&emm_partial_index_inner_int, digest, sizeof(size_t));

        
        pos1 = emm_partial_index_inner_int * seed1 % this->emm_partial_size;
        pos2 = emm_partial_index_inner_int * seed2 % this->emm_partial_size;

        byte_t *emm_partial_payload = (byte_t *) malloc(this->emm_partial_payload_len * sizeof(byte_t));
        if (this->in_memory == true)
            CuckooHasing::Lookup(this->emm_partial+offset, this->emm_partial_payload_len, this->emm_partial_size, pos1, pos2, digest, emm_partial_payload);
        else
            CuckooHasing::LookupSSD(this->folder_emm + "emm_partial.bin", this->emm_partial_payload_len, this->emm_partial_size, pos1+offset, pos2+offset, digest, emm_partial_payload);

        (*response_partial).push_back(emm_partial_payload);
    }
}



void Server::ExecuteQueryFullPages(byte_t *emm_len_index, byte_t *emm_len_XOR_key, byte_t *token,
    std::vector<byte_t*> *response_full, std::vector<byte_t*> *response_partial) {

    /* Get query response volume */
    size_t emm_len_index_int = 0;
    std::memcpy(&emm_len_index_int, emm_len_index, sizeof(size_t));
    size_t pos1 = emm_len_index_int * this->seed_emm_len[0] % this->emm_len_size;
    size_t pos2 = emm_len_index_int * this->seed_emm_len[1] % this->emm_len_size;

    byte_t *emm_len_payload = (byte_t *) malloc(this->emm_len_payload_len * sizeof(byte_t));
    if (this->in_memory == true)
        CuckooHasing::Lookup(this->emm_len, this->emm_len_payload_len, this->emm_len_size, pos1, pos2, emm_len_index, emm_len_payload);
    else
        CuckooHasing::LookupSSD(this->folder_emm + "emm_len.bin", this->emm_len_payload_len, this->emm_len_size, pos1, pos2, emm_len_index, emm_len_payload);

    for (int ii = 0; ii < S1C_emm_len_XOR_key_len; ii++)
        emm_len_payload[ii] ^= emm_len_XOR_key[ii];

    size_t val_len = 0;
    std::memcpy(&val_len, emm_len_payload, sizeof(size_t));

    /* Calculate where to retrieve the documents */
    
    size_t N_full_pages = val_len / this->usable_slots;
    size_t remainder = val_len - N_full_pages * this->usable_slots;

    /* Retrieve documents from emm_full */
    byte_t hash_input_pages[sizeof(size_t) + digest_len];
    size_t emm_full_page_index_int = 0;
    byte_t digest[digest_len];

    std::memcpy(hash_input_pages+sizeof(size_t), token, digest_len);

    for (size_t jj = 0; jj < N_full_pages; jj++) {
        /* Compute the emm key for the jj-th page */
        std::memcpy(hash_input_pages, &jj, sizeof(size_t));
        Hash::HMAC_SHA256_raw(hash_input_pages, sizeof(size_t) + digest_len, digest);

        std::memcpy(&emm_full_page_index_int, digest, sizeof(size_t));

        pos1 = emm_full_page_index_int * this->seed_emm_full[0] % this->emm_full_size;
        pos2 = emm_full_page_index_int * this->seed_emm_full[1] % this->emm_full_size;

        byte_t *emm_full_payload = (byte_t *) malloc(this->emm_full_payload_len * sizeof(byte_t));
        if (this->in_memory == true)
            CuckooHasing::Lookup(this->emm_full, this->emm_full_payload_len, this->emm_full_size, pos1, pos2, digest, emm_full_payload);
        else
            CuckooHasing::LookupSSD(this->folder_emm + "emm_full.bin", this->emm_full_payload_len, this->emm_full_size, pos1, pos2, digest, emm_full_payload);

        (*response_full).push_back(emm_full_payload);
    }
}