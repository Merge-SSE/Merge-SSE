#include <cstring>

#include "Types.hpp"
#include "Client.hpp"
#include "Server.hpp"

#include <iostream>
#include <string>


int BenchmarkFullPages(std::string filename, std::string folder_emm, bool in_memory);
int BenchmarkQueries(std::string filename,std::string folder_emm, bool in_memory,  bool sparsedb_bool, size_t N_updates);

void SearchQuery(std::string keyword, Client *client, Server *server_dummy1C, Server *server_partial);
void UpdateQuery(std::string keyword, byte_t *value, Client *client, Server *server_dummy1C, Server *server_partial);
size_t ReadMM(std::string filename, std::unordered_map<std::string, std::vector<byte_t *>> *multimap);