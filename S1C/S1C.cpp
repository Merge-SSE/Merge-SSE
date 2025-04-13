#include <openssl/conf.h>

#include <cmath>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>


#include "S1C.hpp"
#include "AES.hpp"
#include "Hash.hpp"
#include "Types.hpp"
#include "Client.hpp"
#include "Server.hpp"
#include "CLI11.hpp"


int main(int argc, char** argv) {
    /* Parse arguments */
    CLI::App s1c_args_parser{"Static 1C benchmark"};
    argv = s1c_args_parser.ensure_utf8(argv);

    std::string filename = "../input/inveted_index_5000.txt";
    s1c_args_parser.add_option("-f,--file", filename, "File name of the multi-map");

    std::string folder_emm = "./emm/";
    s1c_args_parser.add_option("-e,--emm", folder_emm, "Folder for storing the EMM");

    bool in_memory = false;
    s1c_args_parser.add_flag("-m,--memory", in_memory, "Run S1C in memory");

    bool benchmark_full_pages_only = false;
    s1c_args_parser.add_flag("--fp,--fullpage", benchmark_full_pages_only, "Benchmark full pages only");

    try {
        s1c_args_parser.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return s1c_args_parser.exit(e);
    }

    if (benchmark_full_pages_only == false)
        BenchmarkQueries(filename, folder_emm, in_memory);
    else
        BenchmarkFullPages(filename, folder_emm, in_memory);

    return 0;
}



int BenchmarkFullPages(std::string filename, std::string folder_emm, bool in_memory) {
    /* Benchmark info */
    long long int setupTime = 0;
    std::vector<unsigned int> query_response_volumes;
    std::vector<long long int> query_response_times;

    Client client;
    client.ReadMM(filename);

    /* Client setup */
    std::chrono::steady_clock::time_point time_begin = std::chrono::steady_clock::now();

    client.KeyGen();
    client.Setup();
    client.SetupFinalize();

    /* Server setup */
    Server server(folder_emm, in_memory);
    

    unsigned int emm_len_payload_len        = S1C_emm_len_XOR_key_len + S1C_emm_len_index_len;
    size_t emm_len_size                     = std::ceil((1 + epsilon) * client.N_KDP);
    unsigned int emm_full_payload_len       = page_size; 
    size_t page_usable_slots                = (page_size - S1C_emm_full_index_len - 16) / S1C_data_size;
    size_t N_page_max                       = std::ceil(client.N_KDP / page_usable_slots);
    size_t emm_full_size                    = std::ceil((1 + epsilon) *  N_page_max);
    unsigned int emm_partial_payload_len    = S1C_data_size + IV_len + S1C_emm_partial_index_len;

    server.Store_emm_info(emm_len_payload_len, emm_len_size, emm_full_payload_len, emm_full_size,
                            emm_partial_payload_len, client.N_bins, std::ceil((1 + epsilon) * client.bincap));
    server.Store_emm_len(client.emm_len);
    server.Store_emm_full(client.emm_full);
    server.Store_emm_partial(client.emm_partial);

    server.Store_seeds(client.seed_emm_len, client.seed_emm_full, client.seed_emm_partial);

    std::chrono::steady_clock::time_point time_end = std::chrono::steady_clock::now();
    setupTime = std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count();

    std::cout << "Setup done: " << setupTime/1000000.0 << " ms" << std::endl;
    
    byte_t emm_len_index[S1C_emm_len_index_len];
    byte_t emm_len_XOR_key[S1C_emm_len_XOR_key_len];
    byte_t token[digest_len];

    /* Run queries */
    unsigned int counter = 0;
    std::unordered_map<std::string, std::vector<std::string>> *mmap_plaintext = client.getPlaintextMM();
    for (auto kvp: *mmap_plaintext) {
        if (kvp.second.size() < client.usable_slots)
            continue;
            
        std::vector<byte_t*> response_full;
        std::vector<byte_t*> response_partial;
        time_begin = std::chrono::steady_clock::now();

        client.SearchTokenGen(kvp.first, emm_len_index, emm_len_XOR_key, token);
        server.ExecuteQuery(emm_len_index, emm_len_XOR_key, token, &response_full, &response_partial);
        client.DecryptResponse(&response_full, &response_partial);

        time_end = std::chrono::steady_clock::now();
        response_full.clear();
        response_partial.clear();

        query_response_volumes.push_back(kvp.second.size());
        query_response_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count());
        std::cout << "Search time: " << query_response_times.back()/1000000.0 << " ms (" << query_response_volumes.back() << ")" << std::endl;

        if (counter % 100 == 0)
            std::cout << "Query progress: " << counter << std::endl;

        counter ++;
    }

    /* Dump the benchmark results */
    std::ofstream benchmark_file;

    std::stringstream filename_stream;
    filename_stream << "../benchmarks/S1C-opt-p/S1C_benchmark_" << client.N_keywords << "_" << client.N_KDP << "_" << page_size << ".txt"; 

    benchmark_file.open(filename_stream.str());
    if (benchmark_file.is_open()) {
        benchmark_file << client.N_keywords << std::endl;
        benchmark_file << client.N_KDP << std::endl;
        benchmark_file << setupTime << std::endl;
        std::vector<unsigned int>::const_iterator query_response_volumes_iter = query_response_volumes.begin();
        std::vector<long long int>::const_iterator query_response_times_iter = query_response_times.begin();

        while (query_response_volumes_iter != query_response_volumes.end()) {
            benchmark_file << *query_response_volumes_iter << "," << *query_response_times_iter << std::endl;
            ++query_response_volumes_iter;
            ++query_response_times_iter;
        }

    } else {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    return 0;
}


int BenchmarkQueries(std::string filename, std::string folder_emm, bool in_memory) {
    /* Benchmark info */
    long long int setupTime = 0;
    std::vector<unsigned int> query_response_volumes;
    std::vector<long long int> query_response_times;

    Client client;
    client.ReadMM(filename);

    /* Client setup */
    std::chrono::steady_clock::time_point time_begin = std::chrono::steady_clock::now();

    client.KeyGen();
    client.Setup();
    client.SetupFinalize();

    /* Server setup */
    Server server(folder_emm, in_memory);
    

    unsigned int emm_len_payload_len        = S1C_emm_len_XOR_key_len + S1C_emm_len_index_len;
    size_t emm_len_size                     = std::ceil((1 + epsilon) * client.N_KDP);
    unsigned int emm_full_payload_len       = page_size; 
    size_t page_usable_slots                = (page_size - S1C_emm_full_index_len - 16) / S1C_data_size;
    size_t N_page_max                       = std::ceil(client.N_KDP / page_usable_slots);
    size_t emm_full_size                    = std::ceil((1 + epsilon) *  N_page_max);
    unsigned int emm_partial_payload_len    = S1C_data_size + IV_len + S1C_emm_partial_index_len;

    server.Store_emm_info(emm_len_payload_len, emm_len_size, emm_full_payload_len, emm_full_size,
                            emm_partial_payload_len, client.N_bins, std::ceil((1 + epsilon) * client.bincap));
    server.Store_emm_len(client.emm_len);
    server.Store_emm_full(client.emm_full);
    server.Store_emm_partial(client.emm_partial);

    server.Store_seeds(client.seed_emm_len, client.seed_emm_full, client.seed_emm_partial);

    std::chrono::steady_clock::time_point time_end = std::chrono::steady_clock::now();
    setupTime = std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count();

    std::cout << "Setup done: " << setupTime/1000000.0 << " ms" << std::endl;
    
    byte_t emm_len_index[S1C_emm_len_index_len];
    byte_t emm_len_XOR_key[S1C_emm_len_XOR_key_len];
    byte_t token[digest_len];

    /* Run queries */
    unsigned int counter = 0;
    std::unordered_map<std::string, std::vector<std::string>> *mmap_plaintext = client.getPlaintextMM();
    for (auto kvp: *mmap_plaintext) {
        std::vector<byte_t*> response_full;
        std::vector<byte_t*> response_partial;
        time_begin = std::chrono::steady_clock::now();

        client.SearchTokenGen(kvp.first, emm_len_index, emm_len_XOR_key, token);
        server.ExecuteQuery(emm_len_index, emm_len_XOR_key, token, &response_full, &response_partial);
        client.DecryptResponse(&response_full, &response_partial);

        time_end = std::chrono::steady_clock::now();
        response_full.clear();
        response_partial.clear();

        query_response_volumes.push_back(kvp.second.size());
        query_response_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count());
        std::cout << "Search time: " << query_response_times.back()/1000000.0 << " ms (" << query_response_volumes.back() << ")" << std::endl;

        if (counter % 100 == 0)
            std::cout << "Query progress: " << counter << std::endl;

        counter ++;
    }

    /* Dump the benchmark results */
    std::ofstream benchmark_file;

    std::stringstream filename_stream;
    filename_stream << "../benchmarks/S1C-all/S1C_benchmark_" << client.N_keywords << "_" << client.N_KDP << ".txt"; 

    benchmark_file.open(filename_stream.str());
    if (benchmark_file.is_open()) {
        benchmark_file << client.N_keywords << std::endl;
        benchmark_file << client.N_KDP << std::endl;
        benchmark_file << setupTime << std::endl;
        std::vector<unsigned int>::const_iterator query_response_volumes_iter = query_response_volumes.begin();
        std::vector<long long int>::const_iterator query_response_times_iter = query_response_times.begin();

        while (query_response_volumes_iter != query_response_volumes.end()) {
            benchmark_file << *query_response_volumes_iter << "," << *query_response_times_iter << std::endl;
            ++query_response_volumes_iter;
            ++query_response_times_iter;
        }

    } else {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    return 0;

}