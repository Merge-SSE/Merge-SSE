#ifndef TYPES_H
#define TYPES_H


typedef unsigned char byte_t;

constexpr unsigned int lambda = 128;

constexpr unsigned int logLogLambda = 3;
constexpr unsigned int bincap_const = 1;

extern double delta;

extern unsigned int page_size;
extern bool verbose_setup;
constexpr unsigned int data_size = 16;

constexpr unsigned int emm_index_len = 16;

constexpr unsigned int nonce_len = 32;

#endif