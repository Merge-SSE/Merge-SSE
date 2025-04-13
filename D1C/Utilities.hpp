#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>
#include "Types.hpp"

std::string base64_encode(byte_t* bytes_to_encode, unsigned int in_len);

#endif