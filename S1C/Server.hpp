#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <unordered_map>
#include <string>

#include "Hash.hpp"
#include "Types.hpp"

class Server
{
    private:
        std::string folder_emm; 
        bool in_memory;

        byte_t *emm_len;
        byte_t *emm_full;
        byte_t *emm_partial;
        unsigned int emm_len_payload_len = 0;
        size_t emm_len_size = 0;
        unsigned int emm_full_payload_len = 0; 
        size_t emm_full_size = 0;
        unsigned int emm_partial_payload_len = 0; 
        size_t N_bins = 0;
        size_t emm_partial_size = 0;
        size_t usable_slots = 0;

    public:
        size_t *seed_emm_len;
        size_t *seed_emm_full;
        size_t *seed_emm_partial;

        /* Constructor */
        Server(std::string folder_emm, bool in_memory);

        /* Store emm_len */
        void Store_emm_len(byte_t *emm_len_client);

        /* Store emm_full */
        void Store_emm_full(byte_t *emm_full_client);

        /* Store emm_partial */
        void Store_emm_partial(byte_t *emm_partial_client);

        /* Store information about the emm */
        void Store_emm_info(unsigned int emm_len_payload_len, size_t emm_len_size,
                            unsigned int emm_full_payload_len, size_t emm_full_size,
                            unsigned int emm_partial_payload_len, size_t N_bins, size_t emm_partial_size);

        /* Store seeds */
        void Store_seeds(size_t *seed_emm_len_client, size_t *seed_emm_full_client, size_t *seed_emm_partial_client);

        /* Run query as specified */
        void ExecuteQuery(byte_t *emm_len_index, byte_t *emm_len_XOR_key, byte_t *token,
                            std::vector<byte_t*> *response_full, std::vector<byte_t*> *response_partial);

        void ExecuteQueryFullPages(byte_t *emm_len_index, byte_t *emm_len_XOR_key, byte_t *token,
                            std::vector<byte_t*> *response_full, std::vector<byte_t*> *response_partial);

};



#endif