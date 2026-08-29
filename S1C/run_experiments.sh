#!/usr/bin/env bash
# Runs S1C search benchmarks on the dataset sizes listed under the "S1C" section of
# ../deltas.txt. Unlike D1C, S1C is static, so there is no dense/sparse split and no
# update-query phase.
#
# For each dataset size this invokes:
#   ./S1C.exe -f ../input/inverted_index_<N>.txt -p <page_size> -d <delta>
#
# Output for each run is logged to logs/S1C_<N>.log and a short pass/fail summary is
# printed at the end. S1C.exe itself writes its structured benchmark results to
# ../benchmarks/.
#
# Usage: ./run_experiments.sh -p <page_size>

set -euo pipefail

# Run from the S1C/ directory regardless of where the script is invoked from,
# since S1C.exe resolves ../input and ../benchmarks relative to its own cwd.
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
    echo "Error: -p <page_size> is required (should be the optimal page size found via find_page_size.sh)" >&2
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

# Extracts "- 10K: 0.9" style lines out of a named section of deltas.txt.
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

entries="$(list_section "S1C" "$deltas_file")"
if [ -z "$entries" ]; then
    echo "Error: could not find an 'S1C' section with entries in $deltas_file" >&2
    exit 1
fi

mkdir -p logs

printf "%-10s %-10s %-20s %-10s %s\n" "N" "Delta" "Status" "Seconds" "Log"
while IFS=',' read -r label delta; do
    n=$(( ${label%K} * 1000 ))
    input_file="../input/inverted_index_${n}.txt"

    if [ ! -f "$input_file" ]; then
        printf "%-10s %-10s %-20s %-10s %s\n" "$n" "$delta" "MISSING INPUT" "-" "$input_file"
        continue
    fi

    log_file="logs/S1C_${n}.log"

    echo "Running S1C: N=$n delta=$delta p=$page_size ..." >&2
    start_time=$(date +%s)

    set +e
    ./S1C.exe -f "$input_file" -p "$page_size" -d "$delta" > "$log_file" 2>&1
    exit_code=$?
    set -e

    if [ "$exit_code" -eq 0 ]; then
        status="OK"
    else
        status="FAILED (exit $exit_code)"
    fi

    elapsed=$(( $(date +%s) - start_time ))
    printf "%-10s %-10s %-20s %-10s %s\n" "$n" "$delta" "$status" "${elapsed}s" "$log_file"
done <<< "$entries"
