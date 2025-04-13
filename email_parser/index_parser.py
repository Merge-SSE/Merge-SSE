def load_inverted_index(filename):
    inverted_index = {}
    file_input = open(filename, 'r')
    for line in file_input.readlines():
        content = line.split(',')
        keyword = content[0]
        values  = [int(v) for v in content[1:]]
        inverted_index[keyword] = values
    file_input.close()

    return inverted_index


def build_dense_index(inverted_index, page_size):
    inverted_index_dense = {}
    N_KVP, N_keywords = 0, 0

    for keyword in sorted(inverted_index.keys(), key=lambda x:len(inverted_index[x]), reverse=True):
        if (N_KVP + len(inverted_index[keyword])) > (N_keywords + 1) * page_size:
            inverted_index_dense[keyword] = inverted_index[keyword]
            N_KVP += len(inverted_index[keyword])
            N_keywords += 1

    return inverted_index_dense


def build_sparse_index(inverted_index, page_size):
    inverted_index_sparse = {}
    N_KVP, N_keywords = 0, 0

    for keyword in sorted(inverted_index.keys(), key=lambda x:len(inverted_index[x])):
        if (N_KVP + len(inverted_index[keyword])) <= (N_keywords + 1) * page_size:
            inverted_index_sparse[keyword] = inverted_index[keyword]
            N_KVP += len(inverted_index[keyword])
            N_keywords += 1

    return inverted_index_sparse


def dump_inverted_index(inverted_index, filename_output):
    file_output = open(filename_output, 'w')

    for keyword in inverted_index:
        file_output.write(keyword + ',' + ','.join(map(str, inverted_index[keyword])) + '\n')

    file_output.close()


page_size = 254
filename_input = '../input/inveted_index_5000.txt'
dense_output = '../input/inverted_index_dense.txt'
sparse_output = '../input/inverted_index_sparse.txt'

inverted_index = load_inverted_index(filename_input)

inverted_index_dense = build_dense_index(inverted_index, page_size)
inverted_index_sparse = build_sparse_index(inverted_index, page_size)


dump_inverted_index(inverted_index_dense, dense_output)
dump_inverted_index(inverted_index_sparse, sparse_output)
