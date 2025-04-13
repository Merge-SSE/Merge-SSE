#include <openssl/conf.h>

#include <cmath>
#include <chrono>
#include <fstream>
#include <cstring>
#include <sstream>
#include <iostream>
#include <string>

#include "CLI11.hpp"
#include "AES.hpp"
#include "Hash.hpp"
#include "Types.hpp"
#include "Client.hpp"
#include "Server.hpp"
#include "D1C.hpp"



int main(int argc, char** argv) {
    /* Parse arguments */
    CLI::App s1c_args_parser{"Static 1C benchmark"};
    argv = s1c_args_parser.ensure_utf8(argv);

    std::string filename = "../input/inverted_index_10000.txt";
    s1c_args_parser.add_option("-f,--file", filename, "File name of the mulit-map");

    std::string folder_emm = "./emm/";
    s1c_args_parser.add_option("-e,--emm", folder_emm, "Folder for storing the EMM");

    bool in_memory = false;
    s1c_args_parser.add_flag("-m,--memory", in_memory, "Run S1C in memory");

    bool sparsedb_bool = false;
    s1c_args_parser.add_flag("-s,--sparse", sparsedb_bool, "Use this flag to benchmark sparse databases, default is a dense database");

    size_t N_updates = 0;
    s1c_args_parser.add_option("-u,--update", N_updates, "Specify the number of updates in the benchmark, default is 0");

    bool benchmark_full_pages_only = false;
    s1c_args_parser.add_flag("--fp,--fullpage", benchmark_full_pages_only, "Benchmark full pages only");

    try {
        s1c_args_parser.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return s1c_args_parser.exit(e);
    }

    if (benchmark_full_pages_only == false) {
        BenchmarkQueries(filename, folder_emm, in_memory, sparsedb_bool, N_updates);
    } else {
        N_updates = 0;
        BenchmarkFullPages(filename, folder_emm, in_memory);
    }

    return 0;
}


int BenchmarkFullPages(std::string filename, std::string folder_emm, bool in_memory) {
    /* Benchmark info */
    long long int setupTime = 0;
    std::vector<unsigned int> query_response_volumes;
    std::vector<long long int> insertion_times;
    std::vector<long long int> query_response_times;

    /* Load an inverted index */
    std::unordered_map<std::string, std::vector<byte_t *>> multimap;
    size_t N_KDP = ReadMM(filename, &multimap);
    size_t N_labels = multimap.size();


    std::chrono::steady_clock::time_point time_begin = std::chrono::steady_clock::now();

    /* Initialize the client */
    DBType dbType = SPARSEDB;
    Client client(dbType, N_KDP, N_labels);
    
    /* Initialize the server for full pages */
    Server server_dummy1C(folder_emm+"full.bin", in_memory);
    size_t bincap_full = std::ceil((1+epsilon) * client.bincap_full);
    server_dummy1C.StoreEMMInfo(page_size, client.N_bins_full, bincap_full);

    /* Initialize the server for paritial pages */
    Server server_partial(folder_emm+"partial.bin", in_memory);
    size_t emm_partial_payload_len = 2*data_size + emm_index_len + IV_len;
    size_t bincap_partial = std::ceil((1+epsilon) * client.bincap_partial);
    server_partial.StoreEMMInfo(emm_partial_payload_len, client.N_bins_partial, bincap_partial);

    client.KeyGen();
    //client.Setup();
    client.Setup_with_MM_fullpages(&multimap);

    server_dummy1C.StoreEMM(client.emm_full, client.seed_emm_full);
    server_partial.StoreEMM(client.emm_partial, client.seed_emm_partial);

    std::chrono::steady_clock::time_point time_end = std::chrono::steady_clock::now();
    setupTime = std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count();

    std::cout << "Setup done: " << setupTime/1000000.0 << " ms" << std::endl;
    std::cout << "-------------------" << std::endl;

    /* Search keywords */
    for (auto kvp: multimap) {
        if (kvp.second.size() < client.usable_slots)
            continue;
        std::string keyword = kvp.first;
        //std::cout << "Search keyword: " << keyword << " (" << kvp.second.size() << ")" << std::endl;

        time_begin = std::chrono::steady_clock::now();
        SearchQuery(keyword, &client, &server_dummy1C, &server_partial);
        time_end = std::chrono::steady_clock::now();
        query_response_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count());
        query_response_volumes.push_back(kvp.second.size());
        std::cout << "Search time: " << query_response_times.back()/1000000.0 << " ms (" << query_response_volumes.back() << ")" << std::endl;
    }


    /* Dump the benchmark results */
    std::ofstream benchmark_file;

    std::stringstream filename_stream;
    filename_stream << "../benchmarks/D1C-opt-p/D1C_benchmark_" << N_labels << "_" << N_KDP << "_" << page_size << ".txt";
    benchmark_file.open(filename_stream.str());
    if (benchmark_file.is_open()) {
        benchmark_file << N_labels << std::endl;
        benchmark_file << N_KDP << std::endl;
        benchmark_file << setupTime << std::endl;

        benchmark_file << insertion_times.size() << std::endl;
        std::vector<long long int>::const_iterator insertion_times_iter = insertion_times.begin();
        while (insertion_times_iter != insertion_times.end()) {
            benchmark_file << *insertion_times_iter << std::endl;
            ++insertion_times_iter;
        }

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


int BenchmarkQueries(std::string filename,std::string folder_emm, bool in_memory,  bool sparsedb_bool, size_t N_updates) {
    /* Benchmark info */
    long long int setupTime = 0;
    std::vector<unsigned int> query_response_volumes;
    std::vector<long long int> insertion_times;
    std::vector<long long int> query_response_times;

    /* Load an inverted index */
    std::unordered_map<std::string, std::vector<byte_t *>> multimap;
    size_t N_KDP = ReadMM(filename, &multimap);
    size_t N_labels = multimap.size();

    size_t N_rows_skip = 0;
    size_t N_insertions = 0;
    for (auto kvp: multimap) {
        if (N_insertions >= N_updates)
            break;

        N_rows_skip++;
        N_insertions += kvp.second.size();
    }


    std::chrono::steady_clock::time_point time_begin = std::chrono::steady_clock::now();

    /* Initialize the client */
    DBType dbType = DENSEDB;
    if (sparsedb_bool == true)
        dbType = SPARSEDB;

    Client client(dbType, N_KDP, N_labels);
    
    /* Initialize the server for full pages */
    Server server_dummy1C(folder_emm+"full.bin", in_memory);
    size_t bincap_full = std::ceil((1+epsilon) * client.bincap_full);
    server_dummy1C.StoreEMMInfo(page_size, client.N_bins_full, bincap_full);

    /* Initialize the server for paritial pages */
    Server server_partial(folder_emm+"partial.bin", in_memory);
    size_t emm_partial_payload_len = 2*data_size + emm_index_len + IV_len;
    size_t bincap_partial = std::ceil((1+epsilon) * client.bincap_partial);
    server_partial.StoreEMMInfo(emm_partial_payload_len, client.N_bins_partial, bincap_partial);

    client.KeyGen();
    //client.Setup();
    client.Setup_with_MM(&multimap, N_rows_skip);

    server_dummy1C.StoreEMM(client.emm_full, client.seed_emm_full);
    server_partial.StoreEMM(client.emm_partial, client.seed_emm_partial);

    std::chrono::steady_clock::time_point time_end = std::chrono::steady_clock::now();
    setupTime = std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count();

    std::cout << "Setup done: " << setupTime/1000000.0 << " ms" << std::endl;
    std::cout << "-------------------" << std::endl;


    /* Insert keyword document pairs */
    size_t counter = 0;
    for (auto kvp: multimap) {
        counter += 1;
        if (counter >= N_rows_skip)
            break;
        std::string keyword = kvp.first;
        //std::cout << "Inserting keyword: " << keyword << " (" << kvp.second.size() << ")" << std::endl;
        for (byte_t * value: kvp.second) {
            time_begin = std::chrono::steady_clock::now();
            UpdateQuery(keyword, value, &client, &server_dummy1C, &server_partial);
            time_end = std::chrono::steady_clock::now();
            insertion_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count());
            std::cout << "Insertion time: " << insertion_times.back()/1000000.0 << " ms" << std::endl;
        }
    }
    std::cout << "-------------------" << std::endl;

    /* Search keywords */
    for (auto kvp: multimap) {
        std::string keyword = kvp.first;
        //std::cout << "Search keyword: " << keyword << " (" << kvp.second.size() << ")" << std::endl;

        time_begin = std::chrono::steady_clock::now();
        SearchQuery(keyword, &client, &server_dummy1C, &server_partial);
        time_end = std::chrono::steady_clock::now();
        query_response_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds> (time_end - time_begin).count());
        query_response_volumes.push_back(kvp.second.size());
        std::cout << "Search time: " << query_response_times.back()/1000000.0 << " ms (" << query_response_volumes.back() << ")" << std::endl;
    }


    /* Dump the benchmark results */
    std::ofstream benchmark_file;

    std::stringstream filename_stream;
    
    if (dbType == SPARSEDB) {
        filename_stream << "../benchmarks/D1C-sparse/D1C_benchmark_" << N_labels << "_" << N_KDP;
        filename_stream << "_sparse.txt";
    }
    else {
        filename_stream << "../benchmarks/D1C-dense/D1C_benchmark_" << N_labels << "_" << N_KDP;
        filename_stream << "_dense.txt";
    }
    benchmark_file.open(filename_stream.str());
    if (benchmark_file.is_open()) {
        benchmark_file << N_labels << std::endl;
        benchmark_file << N_KDP << std::endl;
        benchmark_file << setupTime << std::endl;

        benchmark_file << insertion_times.size() << std::endl;
        std::vector<long long int>::const_iterator insertion_times_iter = insertion_times.begin();
        while (insertion_times_iter != insertion_times.end()) {
            benchmark_file << *insertion_times_iter << std::endl;
            ++insertion_times_iter;
        }

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



size_t ReadMM(std::string filename, std::unordered_map<std::string, std::vector<byte_t *>> *multimap) {
    std::ifstream inputFile(filename);

    size_t N_KDP = 0;
    
    if (inputFile.is_open()) {
        std::string line;
        size_t pos = 0;
        while (getline(inputFile, line)) {
            /* Get the keyword */
            pos = line.find(",");
            std::string keyword = line.substr(0, pos);
            line.erase(0, pos + 1);

            /* Get the document identifiers */
            std::vector<byte_t *> values;
            while ((pos = line.find(",")) != std::string::npos) {
                std::string value = line.substr(0, pos);
                byte_t *payload = (byte_t *) calloc(data_size, sizeof(byte_t));
                std::memcpy(payload, value.c_str(), value.size());
                values.push_back(payload);
                line.erase(0, pos + 1);
            }
            std::string value = line.substr(0, pos);
            byte_t *payload = (byte_t *) calloc(data_size, sizeof(byte_t));
            std::memcpy(payload, value.c_str(), value.size());
            values.push_back(payload);

            if (keyword.length() > data_size)
                continue;

            (*multimap)[keyword] = values;
            N_KDP += values.size();
        }
        inputFile.close();
    }
    std::cout << "Index read." << std::endl;
    std::cout << "# keywords: " << (*multimap).size() << std::endl;
    std::cout << "# KDP: " << N_KDP << std::endl;
    std::cout << "---------------------" << std::endl;
    return N_KDP;
}


void SearchQuery(std::string keyword, Client *client, Server *server_dummy1C, Server *server_partial) {
    /* Get full pages */
    std::vector<byte_t *> tokens;
    client->SearchTokenGenDummy1C(keyword, &tokens);

    /*
    for (auto entry: client->keyword_counter_full) {
        std::cout << entry.first << ": " << entry.second << std::endl;
    }
    std::cout << "Tokens len: " << tokens.size() << std::endl;
    */

    std::vector<byte_t *> responses;
    server_dummy1C->SearchQueryDummy1C(tokens, &responses);
    client->DecryptSearchResponseDummy1C(&tokens, &responses);

    //std::cout << client->keyword_counter_full[keyword] << "," << responses.size() << std::endl;
    
    /* Get partial pages */
    byte_t *token = (byte_t *) malloc(emm_index_len * sizeof(byte_t));
    size_t gamma_partial = 0;
    client->SearchTokenGenPartial(keyword, token, &gamma_partial);
    //std::cout << "Search gamma partial: " << gamma_partial << std::endl;
    //std::cout << "Counter partial: " << client->keyword_counter_partial[keyword] << std::endl;
    responses.clear();
    server_partial->SearchQueryPartial(gamma_partial, token, client->keyword_counter_partial[keyword], &responses);
    client->DecryptSearchResponsePartial(token, &responses);
    responses.clear();

    /* Get response from the client state */
    client->SearchQueryStash(keyword);
}


void UpdateQuery(std::string keyword, byte_t *value, Client *client, Server *server_dummy1C, Server *server_partial) {
    /* Update server_dummy1C */
    client->UpdateInitialize(keyword, value);
    byte_t token[emm_index_len];
    size_t gamma = client->UpdateGammaGen(token);
    //std::cout << "Gamma: " << gamma << std::endl;

    size_t response_size_full = 2 * server_dummy1C->emm_payload_len * server_dummy1C->emm_bin_size;
    byte_t *response_full = (byte_t*) malloc(response_size_full * sizeof(size_t));
    server_dummy1C->UpdateQueryRetrieve(gamma, response_full);
    //std::cout << "Full pages retrieved." << std::endl;

    std::unordered_map<size_t, byte_t*> mm_bin;
    client->DecryptHashTableDummy1C(response_full, page_size-IV_len, page_size, server_dummy1C->emm_bin_size, &mm_bin);
    //std::cout << "Response size: " << mm_bin.size() << std::endl;

    
    if (client->queryTypeFull == REAL) {
        client->UpdateMMBinDummy1C(token, &mm_bin);
        //std::cout << "Here" << std::endl;
    }
    client->ReencryptMMDummy1C(mm_bin, response_full, client->seed_emm_full+2*gamma);
    server_dummy1C->UpdateQueryStore(gamma, response_full, client->seed_emm_full+2*gamma);
    free(response_full);

    //std::cout << "Full page update completed." << std::endl;


    /* Update server_partial */
    if (client->counter_flush < client->N_bins_partial) {
        size_t response_size_partial = 2 * server_partial->emm_payload_len * server_partial->emm_bin_size;
        //std::cout << "Partial response size: " << response_size_partial << std::endl;
        byte_t *response_partial = (byte_t*) malloc(response_size_partial * sizeof(size_t));
        byte_t *hash_table_partial_new = (byte_t*) malloc(response_size_partial * sizeof(size_t));
        server_partial->UpdateQueryRetrieve(client->counter_flush, response_partial);

        client->UpdateFinalize(response_partial, hash_table_partial_new);
        server_partial->UpdateQueryStore(client->counter_flush, hash_table_partial_new, client->seed_emm_partial+2*client->counter_flush);

        free(response_partial);
        free(hash_table_partial_new);
    }

    //std::cout << "Partial page update completed." << std::endl;
    //std::cout << "---------------------------------" << std::endl;
}