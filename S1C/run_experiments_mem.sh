#!/usr/bin/env bash
# Runs S1C's search benchmark in in-memory mode (-m) on the largest dataset (400K docs),
# for comparison against the on-disk results from run_experiments.sh.
#
# Invokes:
#   ./S1C.exe -f ../input/inverted_index_400000.txt -p <page_size> -d <delta> -m
#
# Only the largest dataset is run because ../benchmark_plots/plot_mem_search.py keeps a
# single result per scheme/regime (it does not select "largest" among duplicates), matching
# how the other plot_*.py scripts already only plot the largest instance.
#
# Output is logged to logs/S1C_mem_400000.log. S1C.exe itself writes its structured benchmark
# results to ../benchmarks/mem-results/ (kept separate from ../benchmarks/S1C-all/).
#
# Usage: ./run_experiments_mem.sh -p <page_size>

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

page_size=""

while getopts "p:h" opt; do
    case "$opt" in
        p) page_size="$OPTARG" ;;
        h)
            echo "Usage: $0 -p <page_size>"
            exit 0
            ;;
        *) exit 1 ;;
    esac
done

if [ -z "$page_size" ]; then
    echo "Error: -p <page_size> is required" >&2
    exit 1
fi

if [ ! -x "./S1C.exe" ]; then
    echo "Error: S1C.exe not found in $(pwd). Build it first: g++ *.cpp -o S1C.exe -lcrypto -lssl" >&2
    exit 1
fi

deltas_file="../deltas.txt"
if [ ! -f "$deltas_file" ]; then
    echo "Error: deltas.txt not found at $deltas_file" >&2
    exit 1
fi

list_section() {
    local section="$1" file="$2"
    awk -v section="$section" '
        $0 == section { insec = 1; next }
        insec && $0 == "" { insec = 0 }
        insec {
            line = $0
            sub(/^- /, "", line)
            split(line, parts, ": ")
            print parts[1] "," parts[2]
        }
    ' "$file"
}

n=400000
delta="$(list_section "S1C" "$deltas_file" | awk -F',' -v want="400K" '$1 == want { print $2 }')"
if [ -z "$delta" ]; then
    echo "Error: no S1C delta for 400K in $deltas_file" >&2
    exit 1
fi

input_file="../input/inverted_index_${n}.txt"
if [ ! -f "$input_file" ]; then
    echo "Error: input file not found: $input_file" >&2
    exit 1
fi

mkdir -p logs
log_file="logs/S1C_mem_${n}.log"

echo "Running S1C (in-memory): N=$n delta=$delta p=$page_size ..." >&2
start_time=$(date +%s)

set +e
./S1C.exe -f "$input_file" -p "$page_size" -d "$delta" -m > "$log_file" 2>&1
exit_code=$?
set -e

if [ "$exit_code" -eq 0 ]; then
    status="OK"
else
    status="FAILED (exit $exit_code)"
fi

elapsed=$(( $(date +%s) - start_time ))
printf "%-10s %-10s %-20s %-10s %s\n" "$n" "$delta" "$status" "${elapsed}s" "$log_file"
echo "Result written to ../benchmarks/mem-results/"
