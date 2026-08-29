#!/usr/bin/env bash
# Sweeps page sizes in D1C's full-page-only mode to help find the optimal page_size
# (see README.md, "Compile D1C and benchmark its full page performance").
#
# For each page size this invokes:
#   ./D1C.exe -f <input> --fp -p <page_size> [-d <delta>]
#
# Output for each run is logged to logs/D1C_optp_<page_size>.log. D1C.exe itself writes
# its structured benchmark results to ../benchmarks/D1C-opt-p/, which
# ../benchmark_plots/benchmark_page_size_D1C.py reads to plot throughput vs. page size.
#
# Usage: ./find_page_size.sh [-f input_file] [-d delta] [-P "256 512 1024 2048 4096 8192"]

set -euo pipefail

# Run from the D1C/ directory regardless of where the script is invoked from,
# since D1C.exe resolves ../input and ../benchmarks relative to its own cwd.
cd "$(dirname "${BASH_SOURCE[0]}")"

input_file="../input/inverted_index_400000.txt"
delta=""
page_sizes="256 512 1024 2048 4096 8192"

while getopts "f:d:P:h" opt; do
    case "$opt" in
        f) input_file="$OPTARG" ;;
        d) delta="$OPTARG" ;;
        P) page_sizes="$OPTARG" ;;
        h)
            echo "Usage: $0 [-f input_file] [-d delta] [-P \"page sizes\"]"
            exit 0
            ;;
        *) exit 1 ;;
    esac
done

if [ ! -x "./D1C.exe" ]; then
    echo "Error: D1C.exe not found in $(pwd). Build it first: g++ *.cpp -o D1C.exe -lcrypto -lssl" >&2
    exit 1
fi

if [ ! -f "$input_file" ]; then
    echo "Error: input file not found: $input_file" >&2
    exit 1
fi

mkdir -p logs

printf "%-10s %-20s %-10s %s\n" "PageSize" "Status" "Seconds" "Log"
for page_size in $page_sizes; do
    log_file="logs/D1C_optp_${page_size}.log"

    args=(-f "$input_file" --fp -p "$page_size")
    if [ -n "$delta" ]; then
        args+=(-d "$delta")
    fi

    echo "Running D1C --fp: page_size=$page_size ${delta:+delta=$delta} ..." >&2
    start_time=$(date +%s)

    set +e
    ./D1C.exe "${args[@]}" > "$log_file" 2>&1
    exit_code=$?
    set -e

    if [ "$exit_code" -eq 0 ]; then
        status="OK"
    else
        status="FAILED (exit $exit_code)"
    fi

    elapsed=$(( $(date +%s) - start_time ))
    printf "%-10s %-20s %-10s %s\n" "$page_size" "$status" "${elapsed}s" "$log_file"
done

echo ""
echo "Results written to ../benchmarks/D1C-opt-p/ -- plot with ../benchmark_plots/benchmark_page_size_D1C.py"
