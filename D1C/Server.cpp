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
Server::Server(std::string filename_emm_client, bool in_memory_client) {
    this->filename_emm = filename_emm_client;
    this->in_memory = in_memory_client;
}

/* Store information about the emm */
void Server::StoreEMMInfo(unsigned int emm_payload_len, size_t N_bins, size_t emm_bin_size) {
    this->emm_payload_len = emm_payload_len;
    this->N_bins = N_bins;
    this->emm_bin_size = emm_bin_size;
}


/* Setup the initial EMM */
void Server::StoreEMM(byte_t *emm, size_t *seed_emm) {
    if (this->in_memory) {
        this->emm = emm;
    }
    else {
        std::ofstream outputFile(this->filename_emm, std::ofstream::binary | std::ofstream::out);
        if (!outputFile.is_open())
            return;
        outputFile.write(reinterpret_cast<const char*>(emm), 2*this->N_bins*this->emm_payload_len*this->emm_bin_size);
        outputFile.close();
    }


    //this->emm = emm;
    this->seed_emm = seed_emm;
}


/* Run a search query for Dummy1C */
void Server::SearchQueryDummy1C(std::vector<byte_t *> tokens, std::vector<byte_t *> *responses) {
    byte_t digest[digest_len];
    size_t gamma = 0;
    size_t offset = 0;
    size_t index = 0;
    size_t pos1 = 0;
    size_t pos2 = 0;

    for (byte_t *token: tokens) {
        Hash::HMAC_SHA256_raw(token, emm_index_len, digest);
        std::memcpy(&gamma, digest, sizeof(size_t));
        gamma = gamma % this->N_bins;

        offset = 2 * gamma * this->emm_payload_len * this->emm_bin_size;

        std::memcpy(&index, token, sizeof(size_t));
        pos1 = index * this->seed_emm[2*gamma] % this->emm_bin_size;
        pos2 = index * this->seed_emm[2*gamma+1] % this->emm_bin_size;

        byte_t *result = (byte_t *) malloc(2 * this->emm_payload_len * sizeof(byte_t));
        if (this->in_memory == true)
            CuckooHasing::LookupDouble(this->emm+offset, this->emm_payload_len, this->emm_bin_size, pos1, pos2, result);
        else
            CuckooHasing::LookupDoubleSSD(this->filename_emm, this->emm_payload_len, this->emm_bin_size, pos1+offset, pos2+offset, result);
        (*responses).push_back(result);
    }
}


/* Run a search query for partial emm */
void Server::SearchQueryPartial(size_t gamma, byte_t * token, size_t counter, std::vector<byte_t *> *responses) {
    byte_t hash_input[emm_index_len+sizeof(size_t)];
    byte_t digest[digest_len];
    size_t offset = 2 * gamma * this->emm_payload_len * this->emm_bin_size;

    size_t index = 0;
    size_t pos1 = 0;
    size_t pos2 = 0;

    std::memcpy(hash_input, token, emm_index_len);

    for (size_t ii = 0; ii < counter; ii++) {
        std::memcpy(hash_input+emm_index_len, &ii, sizeof(size_t));
        Hash::HMAC_SHA256_raw(hash_input, emm_index_len+sizeof(size_t), digest);
        std::memcpy(&index, digest, sizeof(size_t));

        pos1 = index * this->seed_emm[2*gamma] % this->emm_bin_size;
        pos2 = index * this->seed_emm[2*gamma+1] % this->emm_bin_size;

        byte_t *result = (byte_t *) malloc(2 * this->emm_payload_len * sizeof(byte_t));
        if (this->in_memory == true)
            CuckooHasing::LookupDouble(this->emm+offset, this->emm_payload_len, this->emm_bin_size, pos1, pos2, result);
        else
            CuckooHasing::LookupDoubleSSD(this->filename_emm, this->emm_payload_len, this->emm_bin_size, pos1+offset, pos2+offset, result);

        (*responses).push_back(result);
    }
}

/* Run the retrieval phase of the update query */
void Server::UpdateQueryRetrieve(size_t gamma, byte_t *response) {
    size_t offset = 2 * gamma * this->emm_payload_len * this->emm_bin_size;

    if (this->in_memory) {
        std::memcpy(response, this->emm+offset, 2 * this->emm_payload_len * this->emm_bin_size);
    }
    else {
        std::ifstream inputFile(this->filename_emm, std::ifstream::binary);
        inputFile.seekg(offset, inputFile.beg);
        inputFile.read((char *)response, 2 * this->emm_payload_len * this->emm_bin_size);
        inputFile.close();
    }
    
}

/* Run the retrieval phase of the update query */
void Server::UpdateQueryStore(size_t gamma, byte_t *hash_table, size_t *seeds) {
    size_t offset = 2 * gamma * this->emm_payload_len * this->emm_bin_size;
    if (this->in_memory) {
        std::memcpy(this->emm+offset, hash_table, 2 * this->emm_payload_len * this->emm_bin_size);
    }
    else {
        std::ofstream outputFile(this->filename_emm, std::ofstream::binary | std::ofstream::out | std::ofstream::in);
        outputFile.seekp(offset, outputFile.beg);
        outputFile.write(reinterpret_cast<const char*>(hash_table), 2 * this->emm_payload_len * this->emm_bin_size);
        outputFile.close();
    }
    std::memcpy(this->seed_emm+2*gamma, seeds, 2*sizeof(size_t));
}
