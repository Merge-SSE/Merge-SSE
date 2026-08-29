"""
Computes EMM storage costs for S1C and D1C across all dataset sizes listed in deltas.txt,
by parsing the "... client: X bytes" lines that S1C.exe/D1C.exe print during a search
benchmark run (S1C: emm_len + emm_full + emm_partial; D1C: emm_full + emm_partial).

This deliberately does NOT re-derive the cuckoo-hash-table sizing formulas in Python --
those numbers come straight from what the C++ implementation actually computed, so this
script can't drift out of sync with the implementation the way a hardcoded reimplementation
would. It reads the log files that S1C/run_experiments.{ps1,sh} and D1C/run_experiments.{ps1,sh}
already produce, so run those first (see README.md).

Usage:
    python storage.py [-o output.txt]
"""

import argparse
import os
import re


BYTES_PER_GB = 1024 ** 3


def parse_deltas(path):
    """Parses deltas.txt into {section: {size_in_docs: delta}} (same format used by the run scripts)."""
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


def extract_client_bytes(log_path, components):
    """Sums the "<component> client: X [bytes]" lines for the given component names.

    S1C.cpp prints emm_partial as a size_t multiplied by a double (std::ceil(...)),
    which C++ implicitly promotes to double -- for large values that prints in
    scientific notation (e.g. "1.36944e+09"), not a plain integer, so the value
    is parsed as a float rather than matched as \\d+ (which would silently take
    just the "1" before the decimal point).
    """
    pattern = re.compile(r"^(" + "|".join(re.escape(c) for c in components) + r") client:\s*([\d.]+(?:e[+-]?\d+)?)")
    found = {c: None for c in components}
    with open(log_path, "r") as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                found[m.group(1)] = int(float(m.group(2)))

    missing = [c for c, v in found.items() if v is None]
    if missing:
        raise ValueError(f"{log_path}: missing expected line(s) for {missing} "
                          f"(did the run finish successfully? was it produced by run_experiments?)")

    return sum(found.values())


def size_label(n):
    return f"{n // 1000}K"


def collect_storage(deltas, s1c_log_dir, d1c_log_dir):
    """Returns {size_in_docs: {"S1C": bytes, "D1C-dense": bytes, "D1C-sparse": bytes}}."""
    sizes = sorted(deltas["S1C"].keys())
    results = {}

    for n in sizes:
        row = {}

        s1c_log = os.path.join(s1c_log_dir, f"S1C_{n}.log")
        if not os.path.isfile(s1c_log):
            raise FileNotFoundError(f"Missing log: {s1c_log} (run S1C/run_experiments first)")
        row["S1C"] = extract_client_bytes(s1c_log, ["emm_len", "emm_full", "emm_partial"])

        for regime in ("dense", "sparse"):
            d1c_log = os.path.join(d1c_log_dir, f"D1C_{regime}_{n}.log")
            if not os.path.isfile(d1c_log):
                raise FileNotFoundError(f"Missing log: {d1c_log} (run D1C/run_experiments first)")
            row[f"D1C-{regime}"] = extract_client_bytes(d1c_log, ["emm_full", "emm_partial"])

        results[n] = row

    return results


def format_table(results):
    header = f"{'#docs':<8}{'S1C (GB)':>14}{'D1C-dense (GB)':>18}{'D1C-sparse (GB)':>18}"
    lines = [header, "-" * len(header)]

    for n in sorted(results.keys()):
        row = results[n]
        s1c_gb = row["S1C"] / BYTES_PER_GB
        dense_gb = row["D1C-dense"] / BYTES_PER_GB
        sparse_gb = row["D1C-sparse"] / BYTES_PER_GB
        lines.append(f"{size_label(n):<8}{s1c_gb:>14.3f}{dense_gb:>18.3f}{sparse_gb:>18.3f}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compute EMM storage costs for S1C and D1C from benchmark run logs.")
    parser.add_argument("-o", "--output", default=None, help="Write the table to this file instead of stdout")
    parser.add_argument("--deltas", default="deltas.txt", help="Path to deltas.txt (default: ./deltas.txt)")
    parser.add_argument("--s1c-log-dir", default="S1C/logs", help="Directory with S1C_<N>.log files (default: ./S1C/logs)")
    parser.add_argument("--d1c-log-dir", default="D1C/logs", help="Directory with D1C_<regime>_<N>.log files (default: ./D1C/logs)")
    args = parser.parse_args()

    deltas = parse_deltas(args.deltas)
    if "S1C" not in deltas:
        raise ValueError(f"{args.deltas} must contain an 'S1C' section")

    results = collect_storage(deltas, args.s1c_log_dir, args.d1c_log_dir)
    table = format_table(results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(table + "\n")
        print(f"Wrote table to {args.output}")
    else:
        print(table)


if __name__ == "__main__":
    main()
