#ifndef CLIENT_H
#define CLIENT_H

#include <unordered_map>
#include <tuple>
#include <vector>
#include <string>
#include <set>

#include <openssl/rand.h>

#include "AES.hpp"
#include "Hash.hpp"
#include "Types.hpp"


enum QueryTypeFull {
    REAL,
    DUMMY,
};

enum DBType {
    SPARSEDB,
    DENSEDB,
};


class Client
{
    private:
        /* data structures for the 1C function */
        std::unordered_map<std::string, size_t> bin_ids_1C;


        /* Cryptograpic keys */
        byte_t PRF_key_full[PRF_key_len];
        byte_t enc_key_full[enc_key_len];
        byte_t PRF_key_partial[PRF_key_len];
        byte_t enc_key_partial[enc_key_len];

        /* Nonce */
        byte_t nonce[nonce_len];

        /* Stashes */
        std::unordered_map<size_t, std::vector<std::tuple<std::string, byte_t *>>> stash_partial_new;
        std::unordered_map<size_t, std::vector<std::tuple<std::string, byte_t *>>> stash_partial_out;
        std::vector<std::tuple<std::string, byte_t *>> stash_full_new;
        std::unordered_map<size_t, std::tuple<std::string, byte_t *>> stash_full_out;

        std::tuple<std::string, byte_t *> label_payload_update_current;

        

    public:
        DBType dbType;

        size_t N_KDP = 0;
        size_t N_labels = 0;

        /* Insertion counter */
        size_t counter_flush = 0;

        /* 
         * emm_full query type
         * Should be kept private
         * Set to public for convenience !!! 
         */
        QueryTypeFull queryTypeFull;

        /* 
         * Keyword counter_partial records the number of leftover values stored on the server
         * keyword_counter_full records the number of full pages stored on the server
         */
        std::unordered_map<std::string, size_t> keyword_counter_partial;
        std::unordered_map<std::string, size_t> keyword_counter_full;

        /* emm parameters */
        size_t usable_slots = 0;
        size_t N_bins_full = 0;
        size_t bincap_full = 0;

        size_t N_bins_partial = 0;
        size_t bincap_partial = 0;

        /* EMM */
        byte_t *emm_full;
        size_t *seed_emm_full;

        byte_t *emm_partial;
        size_t *seed_emm_partial;

        

        /* Core methods */
        Client(DBType dbType,size_t N_KDP, size_t N_labels);

        /* 
         * Generate the keys for D1C
         * Keys include:
         *   1. 2x 256-bit PRF key used by HMAC-SHA256 to generate subkeys for each keyword.
         *   2. 2x 128-bit encryption key for the payloads 
         *   3. 256-bit nonce
         */
        void KeyGen();

        /* 
         * Setup of Dummy1C + bins
         * No input required
         * Outputs: 
         *   - the full emm (stored in a contiguous byte_t array) and the seeds
         *   - the partial emms (stored in a contiguous byte_t array) and their seeds
         */
        void Setup();

        void Setup_with_MM(std::unordered_map<std::string, std::vector<byte_t *>> *multimap, size_t N_rows_skip);

        void Setup_with_MM_fullpages(std::unordered_map<std::string, std::vector<byte_t *>> *multimap);


        /*
         * Search token generation for Dummy1C
         * Input:
         *   1. keyword: the search keyword
         * Outputs:
         *   1. A vector of tokens (32-byte each)
         */
        void SearchTokenGenDummy1C(std::string keyword, std::vector<byte_t *> *tokens);


        /*
         * Search token generation for partial emm
         * Input:
         *   1. keyword: the search keyword
         * Outputs:
         *   1. A tokens (32-byte)
         *   2. The bin index gamma_partial where the partial indices are stored in 
         */
        void SearchTokenGenPartial(std::string keyword, byte_t *token, size_t *gamma_partial);


        /*
         * Search for the keyword in the client state 
         */
        void SearchQueryStash(std::string keyword);



        /*
         * Decrypt query response from Dummy1C
         * The client has to use the tokens to filter the query response
         */
        void DecryptSearchResponseDummy1C(std::vector<byte_t *> *tokens, std::vector<byte_t *> *responses);


        /*
         * Decrypt query response from partial emm
         * The client has to use the tokens to filter the query response
         */
        void DecryptSearchResponsePartial(byte_t *token, std::vector<byte_t *> *responses);


        /*
         * Run the first part of an update query:
         *   1. Add the label-value pair to stash_partial_new
         *   2. If counter_flush == N_labels:
         *     - Update the nonce
         *     - Dump stash_partial_new to stash_partial_out
         *     - Dump stash_full_new to stash_full_out
         */
        void UpdateInitialize(std::string keyword, byte_t *value);


        /*
         * Run the second part of an update query:
         *   1. Get the label-payload pair for the current update
         *   2. Generate the gamma for the current update
         */
        size_t UpdateGammaGen(byte_t *token);

        /* 
         * Generate a real gamma for the keyword
         */
        size_t UpdateGammaGenDummy1C(std::string keyword, byte_t *token);

        /*
         * Decrypt hash table into an unordered map
         * Removes encryptions of zero 
         * hash table entry: payload + index (+ IV)
         * mm_bin format:
         *   - key: index
         *   - value: payload + index
         */
        void DecryptHashTableDummy1C(byte_t *hash_table, int plaintext_len, int block_len, size_t hash_table_size, std::unordered_map<size_t, byte_t*> *mm_bin);


        /*
         * Decrypt hash table into an unordered map
         * Removes encryptions of zero 
         * hash table entry: label (data_size bytes) + value (data_size bytes) (+ IV)
         * mm_bin format:
         *   - key: label (converted to string)
         *   - value: value
         */
        void DecryptHashTablePartial(byte_t *hash_table, int block_len, size_t hash_table_size, std::unordered_map<std::string, std::vector<byte_t*>> *mm_bin);


        /* 
         * Insert the new entry into the decrypted multimap
         */
        void UpdateMMBinDummy1C(byte_t *token, std::unordered_map<size_t, byte_t*> *mm_bin);


        /* 
         * Re-encrypt the multimap
         */
        void ReencryptMMDummy1C(std::unordered_map<size_t, byte_t*> mm_bin, byte_t* hash_table, size_t *seeds);

        /* 
         * Generate a random gamma for the keyword
         */
        size_t RandomGammaGenDummy1C();

        /*
         * Run the final part of an update query:
         *   1. Decrypt a bin and reparse it as label-value pairs
         *   2. Add entries in stash_partial_out to the label-value pairs and empty stash_partial_out
         *   3. Fill new full pages (flush to stash_full_new) and partial emms (re-encrypt and overwrite the old bin)
         */
        void UpdateFinalize(byte_t *response, byte_t *hash_table);
};



#endif