# Overview
This is the library that implements S1C and D1C. Please follow the instructions below to benchmark the two schemes.

# Software dependencies
The library has two dependencies:
- [CLI11](https://github.com/CLIUtils/CLI11) for command line parsing. This has been included as header files in our code already.
- [OpenSSL](https://github.com/openssl/openssl) for encryption and hashing. Follow the instructions on the GitHub page of OpenSSL to install it.

Each script below has a PowerShell version (`.ps1`, for Windows) and a Bash version (`.sh`, for Linux/macOS). Both accept the same flags and produce the same output.

# Workflow
- [ ] Download the Enron email dataset.
- [ ] Parse the emails into inverted indices.
- [ ] Compile S1C and D1C.
- [ ] Find the optimal page size for each scheme.
- [ ] Run the S1C and D1C benchmarks.
- [ ] Run the in-memory benchmarks.
- [ ] Plot the results.
- [ ] Compute storage costs.
- [ ] Benchmark the comparison schemes (SDa[1C], SDa[2C], L-SDd[1C]) on 400K documents.


# 1. Download the Enron email dataset
The Enron email dataset can be downloaded from [here](https://www.cs.cmu.edu/~enron/). You should unzip it into `./emails_raw/`.


# 2. Parse the emails
Navigate to `./email_parser`. For each dataset size you want to benchmark (e.g. 10000, 50000, 100000, 200000, 400000), run:
```
python email_parser.py -n <N_docs>
```
Make sure `path_input` in `email_parser.py` is correct. This produces `../input/inverted_index_<N_docs>.txt`, an inverted index over `N_docs` documents containing all keywords in `include_keywords.txt`.

Dense/sparse databases (needed for D1C's Step 6 below) are generated later, once the optimal page size is known, with `index_parser.py`.


# 3. Compile S1C and D1C
```
cd S1C && g++ *.cpp -o S1C.exe -lcrypto -lssl && cd ..
cd D1C && g++ *.cpp -o D1C.exe -lcrypto -lssl && cd ..
```
Re-run these commands any time the source changes; the scripts below do not rebuild automatically.


# 4. Find the optimal page size
Both schemes take `page_size` (bytes) and `delta` (the cuckoo hash table oversampling factor) as runtime flags — no recompilation needed. The number of values stored in a page is `(page_size - index_len - IV_len) / data_size`, where `index_len` is the PRF digest length (16 bytes), `IV_len` is the AES-CBC IV length (16 bytes), and `data_size` is the label-value length (16 bytes).

Run each scheme's full-page-only benchmark across a sweep of page sizes:
```
# Windows
.\S1C\find_page_size.ps1
.\D1C\find_page_size.ps1

# Linux/macOS
./S1C/find_page_size.sh
./D1C/find_page_size.sh
```
By default these sweep `{256, 512, 1024, 2048, 4096, 8192}` bytes on `../input/inverted_index_400000.txt`; pass `-f`/`-d` to override the input file or delta, and `-P` (Bash) / `-PageSizes` (PowerShell) to override the page-size list. Results are written to `../benchmarks/S1C-opt-p/` and `../benchmarks/D1C-opt-p/`.

Plot throughput vs. page size for both schemes together and pick the optimal value:
```
python benchmark_plots/benchmark_page_size.py
```
This saves `../benchmarks/plots/exp-page-size.pdf`. (`benchmark_page_size_S1C.py`/`benchmark_page_size_D1C.py` still exist as single-scheme alternatives, but `benchmark_page_size.py` is the one to use since it plots both on the same axes.)


# 5. Record the deltas
`deltas.txt` (at the repo root) lists the `delta` to use for each scheme, dataset size, and (for D1C) regime:
```
S1C
- 10K: 0
...

D1C-dense
- 10K: 0.9
...

D1C-sparse
- 10K: 0
...
```
The `run_experiments` scripts in Step 6 read this file directly, so update it here if you want to change any delta.


# 6. Run the benchmarks
## S1C
S1C is static, so there is no dense/sparse split. For each size listed under `S1C` in `deltas.txt`, this runs `S1C.exe -f ../input/inverted_index_<N>.txt -p <page_size> -d <delta>`:
```
# Windows
.\S1C\run_experiments.ps1 -p <page_size>

# Linux/macOS
./S1C/run_experiments.sh -p <page_size>
```
Use the optimal `page_size` found in Step 4. Results are written to `../benchmarks/`. Plot with:
```
python benchmark_plots/plot_S1C_search.py
```
This saves `../benchmarks/plots/exp-S1C-search.pdf`.

## D1C
D1C is dynamic and benchmarks dense and sparse databases separately, so the dense/sparse input files must exist first. For each size listed under `D1C-dense`/`D1C-sparse` in `deltas.txt`, generate them with:
```
for n in 10000 50000 100000 200000 400000; do
    python email_parser/index_parser.py -n $n -p <page_size>
done
```
using the optimal `page_size` found in Step 4.

Then, for each size and regime, this runs `D1C.exe -f ../input/inverted_index_<N>_<regime>.txt -u <n_updates> [-s] -d <delta> -p <page_size>`:
```
# Windows
.\D1C\run_experiments.ps1 -p <page_size> [-u <n_updates>]

# Linux/macOS
./D1C/run_experiments.sh -p <page_size> [-u <n_updates>]
```
`n_updates` (default 1000) is the number of update queries run before the search benchmark; keep it small (a few hundred/thousand) to bound runtime. Results are written to `../benchmarks/D1C-dense/` and `../benchmarks/D1C-sparse/`. Plot with:
```
python benchmark_plots/plot_D1C_search_dense.py
python benchmark_plots/plot_D1C_search_sparse.py -p <page_size>
```
For the sparse plot, `-p`/`--page-size` is optional; when given it draws dashed gridlines at each `usable_slots` boundary (`(page_size - 32) / 16`), bounded to the actual plotted data range. The dense plot takes no arguments (no gridlines, and the same x-axis cutoff as the S1C plot). This saves `../benchmarks/plots/exp-D1C-search-dense.pdf` and `../benchmarks/plots/exp-D1C-search-sparse.pdf`.


# 7. In-memory benchmarks
To compare against an in-memory server (no disk I/O), run the same search benchmark with `-m`/`--memory` on the largest dataset (400K docs) only, for each scheme:
```
# Windows
.\S1C\run_experiments_mem.ps1 -p <page_size>
.\D1C\run_experiments_mem.ps1 -p <page_size> [-u <n_updates>]

# Linux/macOS
./S1C/run_experiments_mem.sh -p <page_size>
./D1C/run_experiments_mem.sh -p <page_size> [-u <n_updates>]
```
Only 400K is run because `plot_mem_search.py` (below) keeps a single result per scheme/regime rather than picking the largest among duplicates, matching how the other plot scripts already only plot the largest instance. Delta is read from `deltas.txt` as in Step 6; D1C runs both the dense and sparse regimes.

Results are written to `../benchmarks/mem-results/` (kept separate from the on-disk results so the two don't overwrite each other). Plot with:
```
python benchmark_plots/plot_mem_search.py -p <page_size>
```
`-p`/`--page-size` is optional (draws gridlines at each `usable_slots` boundary, i.e. `(page_size - 32) / 16`); `--max-vol` (default 300) controls the x-axis range plotted. This saves `../benchmarks/plots/exp-mem.pdf`.


# 8. Storage costs
`storage.py` (at the repo root) computes EMM storage costs (in GB) for S1C and D1C across every size in `deltas.txt`, by parsing the `emm_len`/`emm_full`/`emm_partial` byte counts that `S1C.exe`/`D1C.exe` print during a run. It reads directly from the `S1C/logs/`/`D1C/logs/` files produced in Step 6, so run those first:
```
python storage.py
```
Pass `-o <file>` to write the table to a file instead of printing it.


# 9. Benchmark comparison schemes (DSE-with-IO-Locality-main)
`DSE-with-IO-Locality-main/` is a third-party artifact (Mondal, Chamani, Demertzis, Papadopoulos, "I/O-Efficient Dynamic Searchable Encryption meets Forward & Backward Privacy", USENIX Security 2024), used to compare S1C/D1C against three of its schemes: `SDa[1C]`, `SDa[2C]`, and `L-SDd[1C]`. We only benchmark these three, on the 400K-document dataset.

**This is not the original artifact.** The upstream code is Linux-only and did not build or run correctly on Windows; the copy in this repo has been patched to fix that, plus a few genuine bugs and workflow additions. If you diff against the original repository, expect differences. Summary of what changed:
- **Portability fixes to actually build/run on Windows**: non-portable headers/types (`<aes.h>` → `<openssl/aes.h>`, missing `<cstdint>`, no `uint` typedef, `long` assumed 64-bit), Linux-only AES-NI/build flags, a `std::byte`/`byte` name collision, `sys/sysinfo.h` (unused, removed), and Linux-only shell commands (`dd`/`/dev/zero`, `rm -rf`, `mkdir`, `ulimit`) replaced with portable equivalents.
- **Real crash fixes, not just portability**: several `setup()`-style functions fell off the end without a `return` (undefined behavior masked on the original GCC 5.5 toolchain, but a hard crash on the GCC 13 toolchain used here); `std::rename()` doesn't overwrite an existing destination file on Windows the way POSIX `rename()` does, which broke the de-amortized scheme's level-merge step; `HDD`/`SSD` hardware modes issued a `sudo hdparm`/`sudo nvme` cache-drop command via `system()` before every single search and update (to force real device I/O instead of serving repeat reads from the OS page cache) — these are Linux-only tools with no Windows equivalent, so every call spawned a doomed `cmd.exe` and printed "The system cannot find the path specified", millions of times over a full run. On Windows these are now no-ops, which was undetected until `SSD`/`HDD` were actually exercised (only `Memory` mode, which skips cache-dropping entirely, had been run before) — matching S1C/D1C, which also don't drop the OS page cache between accesses.
- **Resource-usage fixes** (not required for correctness): level files are created empty and grow lazily as they're written instead of being zero-filled to full capacity up front.
- **Performance fix (file-handle churn)**: `Storage`, `OneChoiceStorage`, `TwoChoiceWithOneChoiceStorage`, `TransientStorage`, and `TransientStorage2D` were first changed to keep at most one file handle open at a time per object (closing it whenever a different level was accessed), to reduce open-file-descriptor usage. This backfired badly: the amortized one-choice scheme touches ~log₂(N) (~24 for N=14.27M) levels per single search, so every query turned into dozens of `fopen`/`fclose` calls — invisible when only `Memory` mode (which bypasses this storage layer) had been tested, but responsible for ~80% idle CPU and near-zero throughput once `SSD`/`HDD` modes were actually run. Reverted to keeping one persistent handle open per level for the object's whole lifetime (matching `StorageSDDPiBAS`'s existing design, and the reason `_setmaxstdio(8192)` was already raised on Windows), closing a specific level's handle only when `closeHandle`/`rename`/`resetup` need to rewrite that exact file. Confirmed safe: at N=14.27M, `SDa[1C]`/`SDa[2C]` peak at ~48 simultaneously open handles and `L-SDd[1C]` (which runs 4 parallel one-choice instances for its de-amortized background construction) at ~192 — both far under the raised 8192 cap.
- **Memory leak fix**: `OneChoiceStorage::find()` and `TwoChoiceWithOneChoiceStorage::find()` (the read path used by every search in `SDa[1C]`, `SDa[2C]`, and `L-SDd[1C]`) each allocate up to three `new char[...]` read buffers across their branches, but only one of the three was ever `delete`d — the other two leaked on every call. Since `search()` touches ~log₂(N) levels per query, this leaked roughly two buffers per level per query; observed in practice as `io-dse.exe`'s memory climbing from ~980MB to ~1.95GB in under two minutes during a single-scheme test run. Fixed by freeing all three buffers. While in this code, also corrected several unrelated `delete x` calls on `new char[...]`-allocated arrays (technically undefined behavior; they need `delete[] x`) across `OneChoiceStorage.cpp`, `TwoChoiceWithOneChoiceStorage.cpp`, `Storage.cpp`, `StorageSDDPiBAS.cpp`, `StorageSDd.cpp`, and `NlogNStorage.cpp`.
- **Workflow additions**: `io-dse.exe` used to synthesize a random dataset shaped only by hand-picked `N`/`K`/query-size numbers in `config.txt`, run exactly one hardcoded update query, and print everything to stdout only (no output file, so nothing distinguished one run from another). It now takes `config.txt` and the update-query count (`N_UPDATES`) as CLI arguments (see below), `generate_config.py` builds `config.txt` from the real per-keyword volumes of the actual dataset (via `email_parser/convert_io.py`) instead of arbitrary numbers, updates are run `N_UPDATES` times (not once) so update time can be averaged, and each run writes its results to a uniquely-named file instead of only stdout.

Compile it:
```
cd DSE-with-IO-Locality-main
g++ -std=c++14 -maes -msse4.1 -fno-strict-aliasing -static-libgcc -static-libstdc++ -static *.cpp -o io-dse.exe -lcrypto -lssl
cd ..
```

Convert the raw 400K inverted index into a per-keyword volume file — this must be done before generating the config file below:
```
cd email_parser
python convert_io.py -n 400000
cd ..
```
This produces `input/inverted_index_400000_io.txt`.

Generate `DSE-with-IO-Locality-main/config.txt` from that real data (`N`, `K`, and a sample of real search queries). Each query legitimately costs O(log₂ N) (~24 for N=14.27M) real-disk level reads in this construction, so running the full 32,201-query set on `SSD` takes hours per scheme; 1,000 queries keeps this to a reasonable runtime while still giving good coverage across the volume distribution (see below):
```
cd DSE-with-IO-Locality-main
python generate_config.py -n 400000 -q 1000
```
(Omit `-q` to use every real keyword's query instead, for a slower but fully exhaustive comparison.) When `-q` samples a subset, it spreads the sample evenly across the *log* of query volume, not evenly by rank: real per-keyword volumes are heavily right-skewed (most keywords match very few documents), so a naive rank-even sample mostly picks tiny-result queries (a 2,000-query rank sample here had 73% below volume 100, out of a max of 21,414) and starves the benchmark of the medium/large-result queries that actually show how search time scales with result size.

Run each of the three schemes (SSD, no caching — matching S1C/D1C, which are benchmarked against real disk I/O, not in-memory). Use 1000 update queries for `SDa[1C]`/`SDa[2C]` to match the update-query count used for S1C/D1C; skip updates for `L-SDd[1C]` (`N_UPDATES=0`) since its de-amortized rebuild makes updates far too slow to benchmark this way:
```
# Windows
.\io-dse.exe "SDa[1C]" SSD 0 1000
.\io-dse.exe "SDa[2C]" SSD 0 1000
.\io-dse.exe "L-SDd[1C]" SSD 0 0

# Linux/macOS
./io-dse.exe "SDa[1C]" SSD 0 1000
./io-dse.exe "SDa[2C]" SSD 0 1000
./io-dse.exe "L-SDd[1C]" SSD 0 0
```
Full usage: `io-dse.exe SCHEME_NAME HARDWARE CACHE_SIZE [N_UPDATES] [CONFIG_FILE]` (the last two arguments are optional, defaulting to 100 and `config.txt`; `HDD`/`SSD` are also accepted for `HARDWARE`, and `CACHE_SIZE` is a percentage 0-100). Each run writes its results to `result_<scheme>_<hardware>_cache<cacheSize>_u<N_updates>.txt` in `DSE-with-IO-Locality-main/` — one CSV line per search (`resultSize,microseconds`) and per update (`update,microseconds`), plus a final `update_avg,microseconds` line; the distinct filename per scheme/hardware/cache/update-count means separate runs don't overwrite each other.


# Notes
- All scripts log each run's full output to a `logs/` folder next to the script (e.g. `S1C/logs/`, `D1C/logs/`), and print a pass/fail summary at the end.
- `-p`/`page_size` has no default in `run_experiments`/`index_parser.py` on purpose: passing the wrong page size silently produces meaningless results (dense/sparse partitioning and `usable_slots` both depend on it), so it must be supplied explicitly.
- Add `-v`/`--verbose` when invoking `S1C.exe`/`D1C.exe` directly for detailed cuckoo-hash-table build progress; the scripts don't pass this through by default since it's noisy at scale.
