#!/usr/bin/env bash
# Runs D1C search benchmarks on the dataset sizes listed under the "D1C-dense" and
# "D1C-sparse" sections of ../deltas.txt, in both the dense and sparse regimes.
#
# For each dataset size and regime this invokes:
#   ./D1C.exe -f ../input/inverted_index_<N>_<regime>.txt -u <n_updates> [-s] -d <delta> -p <page_size>
#
# Output for each run is logged to logs/D1C_<regime>_<N>.log and a short pass/fail
# summary is printed at the end. D1C.exe itself writes its structured benchmark results
# to ../benchmarks/D1C-dense/ and ../benchmarks/D1C-sparse/.
#
# Usage: ./run_experiments.sh -p <page_size> [-u <n_updates>]

set -euo pipefail

# Run from the D1C/ directory regardless of where the script is invoked from,
# since D1C.exe resolves ../input and ../benchmarks relative to its own cwd.
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
    echo "       input files were split with (see index_parser.py -p), otherwise usable_slots" >&2
    echo "       won't match how the data was partitioned and results will be meaningless." >&2
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

mkdir -p logs

printf "%-8s %-10s %-10s %-20s %-10s %s\n" "Regime" "N" "Delta" "Status" "Seconds" "Log"
for regime in dense sparse; do
    entries="$(list_section "D1C-$regime" "$deltas_file")"
    if [ -z "$entries" ]; then
        echo "Error: could not find a 'D1C-$regime' section with entries in $deltas_file" >&2
        exit 1
    fi

    while IFS=',' read -r label delta; do
        n=$(( ${label%K} * 1000 ))
        input_file="../input/inverted_index_${n}_${regime}.txt"

        if [ ! -f "$input_file" ]; then
            printf "%-8s %-10s %-10s %-20s %-10s %s\n" "$regime" "$n" "$delta" "MISSING INPUT" "-" "$input_file"
            continue
        fi

        log_file="logs/D1C_${regime}_${n}.log"

        args=(-f "$input_file" -u "$n_updates" -d "$delta" -p "$page_size")
        if [ "$regime" = "sparse" ]; then
            args+=(-s)
        fi

        echo "Running D1C: regime=$regime N=$n delta=$delta p=$page_size u=$n_updates ..." >&2
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
    done <<< "$entries"
done
