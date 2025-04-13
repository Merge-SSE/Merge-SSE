# Overview
This is the library that implements S1C and D1C. Please follow the instructions below to benchmark the two schemes.

# Software dependencies
The library has two dependencies:
- [CLI11](https://github.com/CLIUtils/CLI11) for command line parsing. This has been included as header files in our code already.
- [OpenSSL](https://github.com/openssl/openssl) for encryption and hashing. Follow the instructions on the GitHub page of OpenSSL to install it.

# Benchmark procedures
This section provides a high-level overview of the benchmark procedures. The steps are:
- [ ] Download the Enron email dataset.
- [ ] Parse the emails.
- [ ] Compile S1C and benchmark its full page performance.
- [ ] Benchmark S1C on a general database.
- [ ] Compile D1C and benchmark its full page performance.
- [ ] Benchmark D1C on sparse and dense databases.


# 1. Download the Enron email dataset
The Eonron email dataset can be downloaded from [here](https://www.cs.cmu.edu/~enron/). You should unzip it into `./emails_raw/`.


# 2. Parse the emails
Navigate to `./email_parser`. Run `email_parser.py`. Make sure `path_input` in `email_parser.py` is correct. Adjust the number of emails to include by changing `N_docs` in `email_parser.py`. The output file will appear in `../input/` as `inverted_index_{N_docs}.txt`. The output file is an inverted index containing all keywords in `include_keywords.txt`.

Run `index_parser.py` to further process `inverted_index_{N_docs}.txt` into inverted indices for a dense database and a sparse database. The page size is set by `page_size` in `index_parser.py`. This step will only be used after the optimal page size of D1C has been determined.


# 3. Compile S1C and benchmark its full page performance
Navigate to `./S1C/`. Set the page size (in the number of bytes) in `Types.hpp`. The number of values stored in a page can be derived as
```
(page_size - S1C_emm_full_index_len - IV_len) / data_size
```
where `S1C_emm_full_index_len` is the PRF digest length (typically 16 bytes), `IV_len` is the IV length used in the encryption (AES-$CBC; typically 16 bytes), and `data_size` is the length of the values in the label-value pairs (set to 16 bytes).

Compile SIC by running the following command
```
g++ *.cpp -o S1C.exe -lcrypto -lssl
```

Run S1C in full-page-only mode by using
```
./S1C.exe -f <input_filename> --fp
```
The output will appear in `../benchmarks/S1C-opt-p/` as `S1C_benchmark_{M}_{N}_{page_size}.txt` where `M` is the number of labels and `N` is the number of label-value pairs.

Repeat the procedure above for different choices of `page_size`.

Use `../benchmark_plots/benchmark_page_size _S1C.py` to derive the throughputs of S1C for different chocies of `page_size`. You may need to change the input file names in the Python script.


# 4. Benchmark S1C on a general database
Set `page_size` in `Types.hpp` to the optimal value found in Step 3. Compile SIC by running the following command
```
g++ *.cpp -o S1C.exe -lcrypto -lssl
```

Run S1C by using
```
./S1C.exe -f <input_filename>
```
The output will appear in `../benchmarks/` as `S1C_benchmark_{M}_{N}.txt` where `M` is the number of labels and `N` is the number of label-value pairs.

Repeat the last step above with multi-maps of different size.

Use `../benchmark_plots/plot_S1C_search.py` to plot the search performance of S1C. You may need to change the input file names in the Python script. The setup time (in nanoseconds) can be found on the third line of the benchmark outputs.



# 5. Compile D1C and benchmark its full page performance
Navigate to `./D1C/`. Set the page size (in the number of bytes) in `Types.hpp`. The number of values stored in a page can be derived as
```
(page_size - emm_index_len - IV_len) / data_size
```
where `emm_index_len` is the PRF digest length (typically 16 bytes), `IV_len` is the IV length used in the encryption (AES-$CBC; typically 16 bytes), and `data_size` is the length of the values in the label-value pairs (set to 16 bytes).

Compile D1C by running the following command
```
g++ *.cpp -o D1C.exe -lcrypto -lssl
```

Run D1C in full-page-only mode by using
```
./D1C.exe -f <input_filename> --fp
```
`input_filename` can be the inverted indices used to benchmark S1C as only the full pages will be used.
The output will appear in `../benchmarks/D1C-opt-p/` as `D1C_benchmark_{M}_{N}_{page_size}.txt` where `M` is the number of labels and `N` is the number of label-value pairs. 

Repeat the procedure above for different choices of `page_size`.

Use `../benchmark_plots/benchmark_page_size _D1C.py` to derive the throughputs of S1C for different chocies of `page_size`. You may need to change the input file names in the Python script.


# 6. Benchmark D1C on a general database
Set `page_size` in `Types.hpp` to the optimal value found in Step 5. Compile SIC by running the following command
```
g++ *.cpp -o D1C.exe -lcrypto -lssl
```

Generate sparse and desnse databases using the second half of the procedure from Step 2.

## Dense database ($N \leq pM$)
Run D1C on dense databases by using
```
./D1C.exe -f <input_filename> -u <N_updates>
```
where `N_updates` is the number of update queries to run in the benchmark. It is recommended to set `N_updates` to be relatively small (a few hundred or thousand) to reduce the waiting time of the experiments.
The output will appear in `../benchmarks/D1C-dense/` as `S1C_benchmark_{M}_{N}_dense.txt` where `M` is the number of labels and `N` is the number of label-value pairs.


## Sparse database ($N > pM$)
Run D1C on sparse databases by using
```
./D1C.exe -f <input_filename> -u <N_updates> -s
```
where `N_updates` is the number of update queries to run in the benchmark. It is recommended to set `N_updates` to be relatively small (a few hundred or thousand) to reduce the waiting time of the experiments.
The output will appear in `../benchmarks/D1C-sparse/` as `S1C_benchmark_{M}_{N}_sparse.txt` where `M` is the number of labels and `N` is the number of label-value pairs.