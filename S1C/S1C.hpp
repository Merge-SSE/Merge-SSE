#ifndef S1C_H
#define S1C_H

#include <string>

int BenchmarkFullPages(std::string filename, std::string folder_emm, bool in_memory);
int BenchmarkQueries(std::string filename, std::string folder_emm, bool in_memory);

#endif