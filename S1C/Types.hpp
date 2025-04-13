#ifndef TYPES_H
#define TYPES_H


typedef unsigned char byte_t;

constexpr unsigned int lambda = 128;

constexpr unsigned int logLogLambda = 3;
constexpr unsigned int bincap_const = 1;

constexpr double epsilon = 2;

constexpr unsigned int page_size = 512;
constexpr unsigned int S1C_data_size = 16;

constexpr unsigned int S1C_emm_len_index_len = 16;
constexpr unsigned int S1C_emm_len_XOR_key_len = sizeof(size_t);
constexpr unsigned int S1C_emm_full_index_len = 16;
constexpr unsigned int S1C_emm_partial_index_len = 16;

#endif