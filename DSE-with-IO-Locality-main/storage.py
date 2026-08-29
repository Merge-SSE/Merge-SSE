"""
Computes on-disk storage costs for SDa[1C], SDa[2C], and L-SDd[1C] analytically,
by reimplementing the level/bin-capacity formulas from the C++ storage classes.

Unlike ../storage.py (which parses byte counts that S1C.exe/D1C.exe print
themselves, so it can't drift out of sync with the implementation), io-dse.exe
never logs a storage/byte count anywhere -- there is nothing to parse. This
script is therefore a hardcoded reimplementation of the sizing formulas below,
and WILL silently go stale if those formulas change in the C++ source. Keep it
in sync with:
    OneChoiceStorage.cpp   (SDa[1C] main data, and each of L-SDd[1C]'s 4 instances)
    TwoChoiceWithOneChoiceStorage.cpp (SDa[2C] main data)
    Storage.cpp / Storage.h (keywordCounters, shared by all three)
    DeAmortizedSDdGeneral.cpp, OneChoiceSDdGeneralServer.cpp (L-SDd[1C]'s 4x structure)

Every level's file is preallocated to a fixed size (numberOfBins[i] * sizeOfEachBin[i]
* AES_KEY_SIZE bytes for the main data; 2**(i+1) * KEY_VALUE_SIZE bytes for
keywordCounters) regardless of how full it actually is, so these formulas give
the exact on-disk size -- no need to touch the filesystem.

This excludes TwoChoiceWithOneChoiceStorage's per-level STASH-*.dat overflow files
(cuckoo-eviction overflow), which are sized data-dependently rather than by a fixed
formula; the 4x SPACE_OVERHEAD bin overprovisioning is designed to keep them near-empty,
so SDa[2C]'s true total should be only marginally higher than what this script reports.

Usage:
    python storage.py [-n N] [-o output.txt]
"""

import argparse
import math


AES_KEY_SIZE = 32  # Types.hpp
LONG_SIZE = 4  # sizeof(long) on MinGW-w64/Windows (LLP64)
KEY_VALUE_SIZE = 2 * AES_KEY_SIZE + LONG_SIZE  # Storage.h: KEY_VALUE_SIZE
SPACE_OVERHEAD = 4  # Types.hpp

BYTES_PER_GB = 1024 ** 3


def levels(n):
    """OneChoiceStorage/TwoChoiceWithOneChoiceStorage/DeAmortizedSDdGeneral all use
    this same level count (the binary-counter doubling structure, same as D1C)."""
    return math.floor(math.log2(n)) + 1


def onechoice_bytes(n):
    """SDa[1C]'s main data storage (OneChoiceStorage.cpp:12-13), and the formula
    reused by each of L-SDd[1C]'s 4 parallel instances."""
    total = 0
    for i in range(levels(n)):
        if i <= 1:
            nbins, sbin = 1, 2 ** i
        else:
            nbins = math.ceil((2 ** i) / (i * math.log2(i)))
            sbin = 3 * i * math.log2(i)
        total += nbins * sbin * AES_KEY_SIZE
    return total


def twochoice_bytes(n):
    """SDa[2C]'s main data storage (TwoChoiceWithOneChoiceStorage.cpp:12-14).
    Excludes STASH-*.dat overflow files -- see module docstring."""
    total = 0
    for i in range(levels(n)):
        if i <= 3:
            nbins, sbin = 1, SPACE_OVERHEAD * (2 ** i)
        else:
            loglog = math.log2(math.log2(2 ** i))
            logloglog = math.log2(loglog)
            nbins = math.ceil((2 ** i) / (loglog * logloglog * logloglog))
            nbins = 2 ** math.ceil(math.log2(nbins))
            sbin = SPACE_OVERHEAD * loglog * logloglog * logloglog
        total += nbins * sbin * AES_KEY_SIZE
    return total


def keywordcounters_bytes(n):
    """The keywordCounters `Storage` object attached to every scheme's server
    (Storage.cpp:93: maxSize = 2**(i+1) per level)."""
    return sum((2 ** (i + 1)) * KEY_VALUE_SIZE for i in range(levels(n)))


def collect_storage(n):
    """Returns {scheme: bytes} for SDa[1C], SDa[2C], L-SDd[1C] at the given N
    (total keyword-document pairs, i.e. the same N used by generate_config.py)."""
    kwc = keywordcounters_bytes(n)
    sda1c = onechoice_bytes(n) + kwc
    sda2c = twochoice_bytes(n) + kwc
    lsdd1c = 4 * sda1c  # L-SDd[1C]: 4 independent full-height instances of SDa[1C]'s structure

    return {"SDa[1C]": sda1c, "SDa[2C]": sda2c, "L-SDd[1C]": lsdd1c}


def format_table(n, results):
    header = f"{'scheme':<12}{'storage (GB)':>16}"
    lines = [f"N = {n} ({levels(n)} levels)", header, "-" * len(header)]

    for scheme in ("SDa[1C]", "SDa[2C]", "L-SDd[1C]"):
        gb = results[scheme] / BYTES_PER_GB
        lines.append(f"{scheme:<12}{gb:>16.3f}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Compute analytical on-disk storage costs for SDa[1C], SDa[2C], and L-SDd[1C]."
    )
    parser.add_argument("-n", type=int, default=14265325,
                         help="Total keyword-document pairs, i.e. the N passed to generate_config.py "
                              "(default: 14265325, the 400K-document dataset)")
    parser.add_argument("-o", "--output", default=None, help="Write the table to this file instead of stdout")
    args = parser.parse_args()

    results = collect_storage(args.n)
    table = format_table(args.n, results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(table + "\n")
        print(f"Wrote table to {args.output}")
    else:
        print(table)


if __name__ == "__main__":
    main()
