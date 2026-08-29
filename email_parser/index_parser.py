import argparse


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


def build_dense_index(inverted_index, usable_slots):
    inverted_index_dense = {}
    N_KVP, N_keywords = 0, 0

    for keyword in sorted(inverted_index.keys(), key=lambda x:len(inverted_index[x]), reverse=True):
        if (N_KVP + len(inverted_index[keyword])) >= (N_keywords + 1) * usable_slots:
            inverted_index_dense[keyword] = inverted_index[keyword]
            N_KVP += len(inverted_index[keyword])
            N_keywords += 1

    return inverted_index_dense


def build_sparse_index(inverted_index, usable_slots):
    inverted_index_sparse = {}
    N_KVP, N_keywords = 0, 0

    for keyword in sorted(inverted_index.keys(), key=lambda x:len(inverted_index[x])):
        if (N_KVP + len(inverted_index[keyword])) < (N_keywords + 1) * usable_slots:
            inverted_index_sparse[keyword] = inverted_index[keyword]
            N_KVP += len(inverted_index[keyword])
            N_keywords += 1

    return inverted_index_sparse


def dump_inverted_index(inverted_index, filename_output):
    file_output = open(filename_output, 'w')

    for keyword in inverted_index:
        file_output.write(keyword + ',' + ','.join(map(str, inverted_index[keyword])) + '\n')

    file_output.close()


parser = argparse.ArgumentParser(description="Split an inverted index into dense and sparse databases.")
parser.add_argument('-n', '--n-docs', type=int, default=400000, dest='N_docs',
                     help="Number of documents the input inverted index was built from (default: 400000)")
parser.add_argument('-p', '--page-size', type=int, required=True, dest='page_size',
                     help="Page size used to split keywords into dense/sparse (required, no default -- "
                          "an implicit default risks silently generating input files for the wrong page size)")
args = parser.parse_args()

N_docs = args.N_docs
page_size = args.page_size
filename_input = f'../input/inverted_index_{N_docs}.txt'
dense_output = f'../input/inverted_index_{N_docs}_dense.txt'
sparse_output = f'../input/inverted_index_{N_docs}_sparse.txt'

inverted_index = load_inverted_index(filename_input)

# Matches the usable_slots formula S1C/D1C themselves use: (page_size - index_len - IV_len) / data_size,
# with index_len = IV_len = data_size = 16 bytes. The dense/sparse split is based on how many *items*
# (not bytes) a keyword's postings occupy relative to one page, so it must compare against this
# item-count capacity rather than the raw byte page_size.
usable_slots = (page_size - 32) // 16

inverted_index_dense = build_dense_index(inverted_index, usable_slots)
inverted_index_sparse = build_sparse_index(inverted_index, usable_slots)


dump_inverted_index(inverted_index_dense, dense_output)
dump_inverted_index(inverted_index_sparse, sparse_output)
