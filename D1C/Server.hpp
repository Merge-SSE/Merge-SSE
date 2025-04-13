#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <unordered_map>

#include "Hash.hpp"
#include "Types.hpp"

class Server
{
    private:
        std::string filename_emm; 
        bool in_memory;

        byte_t *emm;
        size_t* seed_emm; 

    public:
        size_t emm_payload_len = 0;
        size_t N_bins = 0;
        size_t emm_bin_size = 0;

        /* Constructor */
        Server(std::string filename_emm_client, bool in_memory_client);

        /* Store information about the emm */
        void StoreEMMInfo(unsigned int emm_payload_len, size_t N_bins, size_t emm_bin_len);

        /* Setup the initial EMM */
        void StoreEMM(byte_t *emm, size_t *seed_emm);

        /* Run a search query for Dummy1C */
        void SearchQueryDummy1C(std::vector<byte_t *> tokens, std::vector<byte_t *> *responses);

        /* Run a search query for partial emm */
        void SearchQueryPartial(size_t gamma, byte_t * token, size_t counter, std::vector<byte_t *> *responses);

        /* Run the retrieval phase of the update query */
        void UpdateQueryRetrieve(size_t gamma, byte_t *response);

        /* Run the retrieval phase of the update query */
        void UpdateQueryStore(size_t gamma, byte_t *hash_table, size_t *seeds);
};



#endif