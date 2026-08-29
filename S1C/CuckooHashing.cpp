#include <cstdlib>
#include <ctime>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>

#include <openssl/err.h>

#include "CuckooHashing.hpp"

// Target load factor used when computing a suggested delta (comfortably below kWarnLoadFactor).
static constexpr double kTargetLoadFactor = 0.4;

// 2-table cuckoo hashing is only guaranteed feasible below ~50% load (Pagh-Rodler threshold);
// beyond that, success probability collapses. We warn here rather than abort outright, since
// small/borderline tables can still occasionally succeed.
static constexpr double kWarnLoadFactor = 0.5;

// Above this load factor, a single failed build attempt (hit LOOP_MAX evictions) is treated as
// proof the insertion won't succeed, rather than just reseeding and trying again forever.
static constexpr double kAbortLoadFactor = 0.7;

// Suggests a delta that would bring the load factor down to kTargetLoadFactor, assuming
// hash_table_size was computed by the caller as ceil((1+delta) * base) for some base.
static double suggest_delta(size_t n_items, size_t hash_table_size) {
    return (n_items * (1.0 + delta)) / (2.0 * kTargetLoadFactor * hash_table_size) - 1.0;
}

void CuckooHasing::Build_hash_table(std::unordered_map<size_t, byte_t*> raw_table, unsigned int block_len,
                                    size_t hash_table_size, byte_t *hash_table, size_t *seed) {
    if (verbose_setup)
        std::cout << "Build_hash_table: block_len=" << block_len << " hash_table_size=" << hash_table_size
                   << " raw_table.size()=" << raw_table.size() << std::endl;

    double load_factor = (double) raw_table.size() / (2.0 * hash_table_size);
    if (load_factor >= 1.0) {
        std::cerr << "Build_hash_table: FATAL - " << raw_table.size() << " items cannot fit in a cuckoo hash table"
                   << " of capacity " << 2 * hash_table_size << " (hash_table_size=" << hash_table_size << "),"
                   << " this insertion can never succeed. Try increasing --delta to at least "
                   << suggest_delta(raw_table.size(), hash_table_size) << " (current delta=" << delta << ")." << std::endl;
        std::exit(1);
    } else if (load_factor >= kWarnLoadFactor) {
        std::cerr << "Build_hash_table: WARNING - load factor " << load_factor * 100 << "% for " << raw_table.size()
                   << " items in a table of capacity " << 2 * hash_table_size << " is at/above the ~50% threshold"
                   << " where 2-table cuckoo hashing is no longer guaranteed feasible; insertion may need many retries"
                   << " or fail outright. Consider increasing --delta to at least "
                   << suggest_delta(raw_table.size(), hash_table_size) << " (current delta=" << delta << ")." << std::endl;
    }

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

    std::srand(std::time(0));

    while (succeed == false) {
        attempt++;
        if (verbose_setup && (attempt % 1000 == 0 || attempt <= 5))
            std::cout << "Build_hash_table: attempt " << attempt << " (hash_table_size=" << hash_table_size
                       << ", n_items=" << raw_table.size() << ")" << std::endl;

        // Step 1: clean up
        for (size_t ii = 0; ii < hash_table_size; ii++)
            hash_table_tmp1[ii] = Hash_empty_flag;
        for (size_t ii = 0; ii < hash_table_size; ii++)
            hash_table_tmp2[ii] = Hash_empty_flag;

        // Step 2: get a new seed
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

                current = swap;

                loop_ctr ++;

                if (loop_ctr == LOOP_MAX)
                    break;   
            }

            if (loop_ctr == LOOP_MAX)
                break;
        }

        if (loop_ctr < LOOP_MAX) {
            succeed = true;
        } else if (load_factor > kAbortLoadFactor) {
            std::cerr << "Build_hash_table: FATAL - load factor " << load_factor * 100 << "% for " << raw_table.size()
                       << " items in a table of capacity " << 2 * hash_table_size << " is above " << kAbortLoadFactor * 100
                       << "%, and the build already failed to place all items within " << LOOP_MAX << " evictions"
                       << " (attempt " << attempt << "); this insertion will not succeed no matter how many times it retries."
                       << " Try increasing --delta to at least " << suggest_delta(raw_table.size(), hash_table_size)
                       << " (current delta=" << delta << ")." << std::endl;
            std::exit(1);
        } else if (verbose_setup && (attempt <= 5 || attempt % 1000 == 0)) {
            std::cout << "Build_hash_table: attempt " << attempt << " failed (hit LOOP_MAX=" << LOOP_MAX
                       << ", hash_table_size=" << hash_table_size << ", n_items=" << raw_table.size() << "), retrying" << std::endl;
        }
    }

    if (verbose_setup)
        std::cout << "Build_hash_table: succeeded after " << attempt << " attempt(s) (hash_table_size=" << hash_table_size
                   << ", n_items=" << raw_table.size() << ")" << std::endl;


    /*
    std::cout << "Raw table:" << std::endl;
    for (auto kvp: raw_table) {
        std::cout << kvp.first << std::endl;
        BIO_dump_fp(stdout, (const char *) kvp.second, 20);
    }
    */

    /* Use the temporary hash tables to insert the actual payload */
    for (size_t ii = 0; ii < hash_table_size; ii++)
        if (hash_table_tmp1[ii] != Hash_empty_flag)
            std::memcpy(hash_table+ii*block_len, raw_table[hash_table_tmp1[ii]], block_len);

    for (size_t ii = 0; ii < hash_table_size; ii++)
        if (hash_table_tmp2[ii] != Hash_empty_flag)
            std::memcpy(hash_table+ii*block_len+block_len*hash_table_size, raw_table[hash_table_tmp2[ii]], block_len);

    delete[] hash_table_tmp1;
    delete[] hash_table_tmp2;
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


void CuckooHasing::LookupSSD(std::string filename, unsigned int block_len, size_t hash_table_size,
                            size_t pos1, size_t pos2, byte_t *fingerprint, byte_t *result) {
    std::ifstream inputFile(filename, std::ifstream::binary | std::ifstream::in);
    inputFile.seekg(pos1*block_len, inputFile.beg);
    inputFile.read((char *)result, block_len);

    for (size_t ii = 0; ii < fingerprint_len; ii++) {
        if (result[block_len-fingerprint_len+ii] != fingerprint[ii])
        {
            inputFile.seekg(pos2*block_len+block_len*hash_table_size, inputFile.beg);
            inputFile.read((char *)result, block_len);
            inputFile.close();
            return;
        }
    }
    inputFile.close();
}