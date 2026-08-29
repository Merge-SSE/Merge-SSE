"""
Generates config.txt for io-dse from a real inverted-index volume file produced by
email_parser/convert_io.py (one line per keyword: its number of matching documents).

N and K are computed from the real data (total keyword-document pairs, number of
distinct keywords). By default every real keyword is used as a search query, so the
benchmark's search coverage matches the actual dataset exactly; pass -q to instead
sample a smaller number of queries evenly across the sorted volume distribution (by
rank), e.g. for a quicker/smaller run.

Usage:
    python generate_config.py [-n N_DOCS] [-q NUM_QUERIES] [-o OUTPUT] [--io-file PATH]
"""

import argparse
import bisect
import math
import os


def load_volumes(io_file):
    if not os.path.isfile(io_file):
        raise FileNotFoundError(
            f"{io_file} not found. Generate it first with: "
            f"python ../email_parser/convert_io.py -n <N_docs>"
        )
    with open(io_file, "r") as f:
        return [int(line.strip()) for line in f if line.strip()]


def sample_queries(volumes, num_queries):
    sorted_vols = sorted(volumes)
    n = len(sorted_vols)
    if num_queries is None or num_queries >= n:
        return sorted_vols
    if num_queries <= 1:
        return sorted_vols[:1]
    # Real per-keyword volumes are heavily right-skewed (Zipfian): most keywords
    # match very few documents, and only a handful match many. Sampling evenly by
    # RANK just reproduces that skew in the sample (e.g. 73% of a 2000-query rank
    # sample landed below volume 100, out of a max of 21414) -- which starves the
    # benchmark of exactly the medium/large-result queries needed to see how
    # search time scales with result size. Sampling evenly in LOG-space of volume
    # instead gives every order of magnitude roughly equal representation; nearby
    # log-targets can map to the same actual keyword where large volumes are rare,
    # which just means that keyword gets queried more than once.
    log_min = math.log(sorted_vols[0])
    log_max = math.log(sorted_vols[-1])
    picks = []
    for i in range(num_queries):
        target_log = log_min + i * (log_max - log_min) / (num_queries - 1)
        target = math.exp(target_log)
        pos = bisect.bisect_left(sorted_vols, target)
        if pos == 0:
            idx = 0
        elif pos == n:
            idx = n - 1
        else:
            before, after = sorted_vols[pos - 1], sorted_vols[pos]
            idx = pos - 1 if (target - before) <= (after - target) else pos
        picks.append(sorted_vols[idx])
    return picks


def main():
    parser = argparse.ArgumentParser(description="Generate config.txt for io-dse from a real per-keyword volume file.")
    parser.add_argument("-n", "--n-docs", type=int, default=400000, dest="N_docs",
                         help="Number of documents the inverted index was built from (default: 400000)")
    parser.add_argument("-q", "--num-queries", type=int, default=None, dest="num_queries",
                         help="Number of search queries to sample from the real volume distribution "
                              "(default: use every real keyword)")
    parser.add_argument("-o", "--output", default="config.txt", help="Output config file path (default: config.txt)")
    parser.add_argument("--io-file", default=None,
                         help="Path to the *_io.txt volume file (default: ../input/inverted_index_<n>_io.txt)")
    args = parser.parse_args()

    io_file = args.io_file or f"../input/inverted_index_{args.N_docs}_io.txt"
    volumes = load_volumes(io_file)

    N = sum(volumes)
    K = len(volumes)
    queries = sample_queries(volumes, args.num_queries)

    with open(args.output, "w") as f:
        f.write(f"{N}\n{K}\n{len(queries)}\n")
        for q in queries:
            f.write(f"{q}\n")

    print(f"Wrote {args.output}: N={N}, K={K}, {len(queries)} queries "
          f"(sizes {queries[0]}..{queries[-1]}), from {io_file}")


if __name__ == "__main__":
    main()
