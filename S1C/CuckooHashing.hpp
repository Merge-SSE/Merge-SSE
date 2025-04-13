#ifndef CUCKOO_HASHING_H
#define CUCKOO_HASHING_H

#include <unordered_map>
#include <string>
#include "Types.hpp"

const unsigned int Hash_empty_flag = 4294967295;
const unsigned int LOOP_MAX  = 60;
const unsigned int fingerprint_len = 16;

class CuckooHasing {
    public:
        /* Method to build a hash table */
        static void Build_hash_table(std::unordered_map<size_t, byte_t*> raw_table, unsigned int block_len,
                                    size_t hash_table_size, byte_t *hash_table, size_t *seed);

        /* Method to lookup a hash table */
        static void Lookup(byte_t *hash_table, unsigned int block_len, size_t hash_table_size,
                            size_t pos1, size_t pos2, byte_t *fingerprint, byte_t *result);

        static void LookupSSD(std::string filename, unsigned int block_len, size_t hash_table_size,
                            size_t pos1, size_t pos2, byte_t *fingerprint, byte_t *result);

};



#endif
