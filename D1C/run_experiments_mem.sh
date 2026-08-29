#!/usr/bin/env bash
# Runs D1C's search benchmark in in-memory mode (-m) on the largest dataset (400K docs), in
# both the dense and sparse regimes, for comparison against the on-disk results from
# run_experiments.sh.
#
# For each regime this invokes:
#   ./D1C.exe -f ../input/inverted_index_400000_<regime>.txt -u <n_updates> [-s] -d <delta> -p <page_size> -m
#
# Only the largest dataset is run because ../benchmark_plots/plot_mem_search.py keeps a
# single result per scheme/regime (it does not select "largest" among duplicates), matching
# how the other plot_*.py scripts already only plot the largest instance.
#
# Output is logged to logs/D1C_mem_<regime>_400000.log. D1C.exe itself writes its structured
# benchmark results to ../benchmarks/mem-results/ (kept separate from ../benchmarks/D1C-dense/
# and ../benchmarks/D1C-sparse/).
#
# Usage: ./run_experiments_mem.sh -p <page_size> [-u <n_updates>]

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

page_size=""
n_updates=1000

while getopts "p:u:h" opt; do
    case "$opt" in
        p) page_size="$OPTARG" ;;
        u) n_updates="$OPTARG" ;;
        h)
            echo "Usage: $0 -p <page_size> [-u <n_updates>]"
            exit 0
            ;;
        *) exit 1 ;;
    esac
done

if [ -z "$page_size" ]; then
    echo "Error: -p <page_size> is required. It must match whatever page_size the dense/sparse" >&2
    echo "       input files were split with (see index_parser.py -p)." >&2
    exit 1
fi

if [ ! -x "./D1C.exe" ]; then
    echo "Error: D1C.exe not found in $(pwd). Build it first: g++ *.cpp -o D1C.exe -lcrypto -lssl" >&2
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
mkdir -p logs

printf "%-8s %-10s %-10s %-20s %-10s %s\n" "Regime" "N" "Delta" "Status" "Seconds" "Log"
for regime in dense sparse; do
    delta="$(list_section "D1C-$regime" "$deltas_file" | awk -F',' -v want="400K" '$1 == want { print $2 }')"
    if [ -z "$delta" ]; then
        echo "Error: no D1C-$regime delta for 400K in $deltas_file" >&2
        exit 1
    fi

    input_file="../input/inverted_index_${n}_${regime}.txt"
    if [ ! -f "$input_file" ]; then
        printf "%-8s %-10s %-10s %-20s %-10s %s\n" "$regime" "$n" "$delta" "MISSING INPUT" "-" "$input_file"
        continue
    fi

    log_file="logs/D1C_mem_${regime}_${n}.log"

    args=(-f "$input_file" -u "$n_updates" -d "$delta" -p "$page_size" -m)
    if [ "$regime" = "sparse" ]; then
        args+=(-s)
    fi

    echo "Running D1C (in-memory): regime=$regime N=$n delta=$delta p=$page_size u=$n_updates ..." >&2
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
    printf "%-8s %-10s %-10s %-20s %-10s %s\n" "$regime" "$n" "$delta" "$status" "${elapsed}s" "$log_file"
done

echo "Results written to ../benchmarks/mem-results/"
