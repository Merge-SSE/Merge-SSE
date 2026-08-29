"""
Generates the LaTeX table summarizing dataset statistics (N, M) and delta for S1C and D1C,
across the dataset sizes listed in deltas.txt.

For each size:
  - The S1C (\\EMMOC) row uses the raw inverted index: input/inverted_index_<N>.txt
  - The D1C (\\DMMOC) row uses the sparse/dense split: input/inverted_index_<N>_sparse.txt
    and input/inverted_index_<N>_dense.txt, shown as "sparse / dense".

N is the total number of keyword-document pairs (sum of values per line); M is the number
of keywords (number of lines). Deltas are read from deltas.txt so the table always reflects
whatever is currently recorded there.

Usage:
    python generate_dataset_table.py [-o output.tex]
"""

import argparse
import os
import re


def parse_deltas(path):
    """Parses deltas.txt into {section: {size_in_docs: delta}}."""
    sections = {}
    current_section = None
    with open(path, "r") as f:
        for raw_line in f:
            line = raw_line.strip()
            if line == "":
                current_section = None
                continue
            match = re.match(r"^-\s*(\d+)K\s*:\s*([\d.]+)\s*$", line)
            if match and current_section is not None:
                size = int(match.group(1)) * 1000
                sections[current_section][size] = float(match.group(2))
            elif current_section is None:
                current_section = line
                sections.setdefault(current_section, {})
    return sections


def count_stats(filename):
    """Returns (N, M) for an inverted index file: N = total values, M = number of keywords."""
    N, M = 0, 0
    with open(filename, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            M += 1
            N += line.count(",")
    return N, M


def fmt_int(n):
    return f"{n:,}"


def fmt_delta(d):
    return f"{d:g}"


def size_label(n):
    return f"{n // 1000}K"


def build_table(deltas, input_dir):
    if "S1C" not in deltas or "D1C-dense" not in deltas or "D1C-sparse" not in deltas:
        raise ValueError("deltas.txt must contain 'S1C', 'D1C-dense', and 'D1C-sparse' sections")

    sizes = sorted(deltas["S1C"].keys())

    rows = []
    for n in sizes:
        raw_file = os.path.join(input_dir, f"inverted_index_{n}.txt")
        sparse_file = os.path.join(input_dir, f"inverted_index_{n}_sparse.txt")
        dense_file = os.path.join(input_dir, f"inverted_index_{n}_dense.txt")

        for path in (raw_file, sparse_file, dense_file):
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Missing input file: {path}")

        N_raw, M_raw = count_stats(raw_file)
        N_sparse, M_sparse = count_stats(sparse_file)
        N_dense, M_dense = count_stats(dense_file)

        delta_s1c = deltas["S1C"][n]
        delta_sparse = deltas["D1C-sparse"][n]
        delta_dense = deltas["D1C-dense"][n]

        rows.append({
            "label": size_label(n),
            "s1c_N": fmt_int(N_raw),
            "s1c_M": fmt_int(M_raw),
            "s1c_delta": fmt_delta(delta_s1c),
            "d1c_N": f"{fmt_int(N_sparse)} / {fmt_int(N_dense)}",
            "d1c_M": f"{fmt_int(M_sparse)} / {fmt_int(M_dense)}",
            "d1c_delta": f"{fmt_delta(delta_sparse)} / {fmt_delta(delta_dense)}",
        })

    lines = []
    lines.append(r"\begin{tabular}{l|ll|l|l}")
    lines.append(r"\#emails & N & M & Scheme & $\delta$ \\ \hline")
    for i, row in enumerate(rows):
        lines.append(
            rf"\multirow{{2}}{{*}}{{{row['label']}}} & {row['s1c_N']} & {row['s1c_M']} & $\EMMOC$ & {row['s1c_delta']} \\"
        )
        lines.append(
            rf" & {row['d1c_N']} & {row['d1c_M']} & $\DMMOC$ & {row['d1c_delta']} \\"
            + (r" \hline" if i < len(rows) - 1 else "")
        )
    lines.append(r"\end{tabular}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate the LaTeX dataset-statistics table.")
    parser.add_argument("-o", "--output", default=None, help="Write the table to this file instead of stdout")
    parser.add_argument("--deltas", default="deltas.txt", help="Path to deltas.txt (default: ./deltas.txt)")
    parser.add_argument("--input-dir", default="input", help="Directory containing inverted_index_*.txt (default: ./input)")
    args = parser.parse_args()

    deltas = parse_deltas(args.deltas)
    table = build_table(deltas, args.input_dir)

    if args.output:
        with open(args.output, "w") as f:
            f.write(table + "\n")
        print(f"Wrote table to {args.output}")
    else:
        print(table)


if __name__ == "__main__":
    main()
