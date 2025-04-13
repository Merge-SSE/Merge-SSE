#ifndef CLIENT_H
#define CLIENT_H

#include <unordered_map>
#include <vector>
#include <string>

#include <openssl/rand.h>

#include "AES.hpp"
#include "Hash.hpp"
#include "Types.hpp"


class Client
{
    private:
        /* Raw data */
        std::unordered_map<std::string, std::vector<std::string>> mmap_plaintext;
        
        /* Cryptograpic keys */
        byte_t PRF_key[PRF_key_len];
        byte_t enc_key[enc_key_len];

        /* Encrypted intermediate data */
        std::unordered_map<size_t, byte_t*> emm_len_raw;
        std::unordered_map<size_t, byte_t*> emm_full_raw;
        std::unordered_map<size_t, byte_t*> *emm_partial_raw;

    public:
        size_t N_keywords = 0;
        size_t N_KDP = 0;

        /* Cuckoo hash parameter */
        size_t seed_emm_len[2] = {};
        size_t seed_emm_full[2] = {};
        size_t *seed_emm_partial;

        /* emm_partial parameters */
        size_t usable_slots = 0;
        size_t N_bins = 0;
        size_t bincap = 0;

        /* EMM */
        byte_t *emm_len;
        byte_t *emm_full;
        byte_t *emm_partial;

        /* Core methods */
        Client() { }

        /* 
         * Generate the keys for S1C
         * Keys include:
         *   1. 256-bit PRF key used by HMAC-SHA256 to generate subkeys for each keyword.
         *   2. 128-bit encryption key for the payloads 
         */
        void KeyGen();


        /*
         * Read input file and parse it as mmap_plaintext
         */
        void ReadMM(std::string filename);

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
        void Setup();


        /*
         * Finalise the setup of S1C by dumping emm_len_raw, emm_full_raw and emm_partial_raw into bloom filters
         * Outputs:
         *   1. emm_len: byte array of size 2 * (1 + epsilon) * N_KDP * (emm_len_XOR_key_len + emm_len_index_len)
         *   2. emm_raw: byte array of size 2 * (1 + epsilon) * ceil(N_KDP / page_size) * page_size
         *   3. emm_partial: byte array of size N_bins * 2 * (1 + epsilon) * bincap * (data_size + emm_partial_index_len)
         */
        void SetupFinalize();

        void SetupFinalizeFullPages();


        /*
         * Search token generation, also used in setup
         * Input:
         *   1. keyword: the search keyword
         * Outputs:
         *   1. emm_len_index (16 bytes): the index in emm_len that is used to store the query response volume for the keyword
         *   2. emm_len_XOR_key (4 bytes): the XOR key used to mask the query response volume
         *   3. token (32 bytes): token used to compute the indices of the insertions (in emm_full and emm_partial)
         */
        void SearchTokenGen(std::string keyword, byte_t *emm_len_index, byte_t *emm_len_XOR_key, byte_t *token);


        /*
         * Decrypt query response
         */
        void DecryptResponse(std::vector<byte_t*> *response_full, std::vector<byte_t*> *response_partial);

        /* Functions for debugging */
        void PrintMM();
        void PrintMMStats();


        byte_t *getEncKey();
        std::unordered_map<std::string, std::vector<std::string>> *getPlaintextMM(); 

};



#endif