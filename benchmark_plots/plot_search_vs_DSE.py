import matplotlib.pyplot as plt
import numpy as np
import os


def extract_query_times_ns(filename, grouping=10, has_updates=True):
    """S1C/D1C benchmark files: 'M', 'N', 'setup_time' header lines, optionally an
    N_updates count + that many update-time lines, then 'volume,time' lines in
    nanoseconds."""
    results = {}

    file_input = open(filename, 'r')

    M = int(file_input.readline())
    N = int(file_input.readline())
    setup_time = int(file_input.readline()) / 10**9
    print(f"{os.path.basename(filename)}  M: {M}  N: {N}  Setup: {setup_time} s")

    if has_updates:
        N_updates = int(file_input.readline())
        for skip in range(N_updates):
            file_input.readline()

    for line in file_input.readlines():
        line = line.split(',')
        query_response_volume = int(line[0])
        query_response_time = int(line[1])

        x = ((query_response_volume // grouping) + 1) * grouping
        y = query_response_time / 10**6  # ns -> ms

        if x not in results:
            results[x] = []
        results[x].append(y)

    file_input.close()

    return results, N


def extract_query_times_dse(filename, grouping=10):
    """DSE-xx result files (see DSE-with-IO-Locality-main/main.cpp) start with a
    'setup,time' line (time in microseconds), then 'volume,time' search lines
    (also microseconds, unlike S1C/D1C's nanoseconds), then switch to
    'update,time' lines for the update benchmark, ending in a trailing
    'update_avg,...' line. Skip anything tagged 'setup'/'update'/'update_avg'."""
    results = {}

    file_input = open(filename, 'r')

    for line in file_input.readlines():
        line = line.strip().split(',')
        if not line or line[0] in ('setup', 'update', 'update_avg'):
            continue

        # totalSearchTime is a C++ double, printed in scientific notation
        # (e.g. "1.01283e+06") for large values by default ostream formatting.
        query_response_volume = int(line[0])
        query_response_time = int(float(line[1]))

        x = ((query_response_volume // grouping) + 1) * grouping
        y = query_response_time / 10**3  # us -> ms

        if x not in results:
            results[x] = []
        results[x].append(y)

    file_input.close()

    return results


def plot_line(data, label, max_vol):
    xs = sorted(x for x in data.keys() if x <= max_vol)
    ys = [np.mean(sorted(data[x])) for x in xs]
    plt.plot(xs, ys, label=label)
    return xs, ys


def max_query_volume(data):
    return max(data.keys()) if data else 0


s1c_dir = '../benchmarks/S1C-all/'
d1c_dense_dir = '../benchmarks/D1C-dense/'
dse_dir = '../DSE-with-IO-Locality-main/'

# DSE-xx sanitizes scheme names for filenames (e.g. "SDa[1C]" -> "SDa-1C-";
# see DSE-with-IO-Locality-main/main.cpp's sanitizeForFilename call).
DSE_SCHEME_FILES = {
    'SDa[1C]': 'result_SDa-1C-_SSD_cache0_u1000.txt',
    'SDa[2C]': 'result_SDa-2C-_SSD_cache0_u1000.txt',
    'L-SDd[1C]': 'result_L-SDd-1C-_SSD_cache0_u0.txt',
}

plt.figure(figsize=(10, 6))

# S1C and D1C: use each scheme's largest-N benchmark file (400K documents,
# matching the DSE-xx dataset size).
biggest_n, biggest_file = max(
    (int(fn.split('_')[-1].split('.')[0]), fn) for fn in os.listdir(s1c_dir)
)
s1c_data, s1c_n = extract_query_times_ns(s1c_dir + biggest_file, has_updates=False)
max_vol = max_query_volume(s1c_data)
plot_line(s1c_data, 'S1C', max_vol)

biggest_n, biggest_file = max(
    (int(fn.split('_')[-2]), fn) for fn in os.listdir(d1c_dense_dir)
)
d1c_data, d1c_n = extract_query_times_ns(d1c_dense_dir + biggest_file, has_updates=True)
plot_line(d1c_data, 'D1C', max_vol)

for label, fn in DSE_SCHEME_FILES.items():
    path = dse_dir + fn
    if not os.path.exists(path):
        print(f"Warning: {path} not found, skipping {label}")
        continue
    data = extract_query_times_dse(path)
    plot_line(data, label, max_vol)

plt.yscale('log')
plt.legend()
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-search-vs-DSE.pdf')
print('Saved plot to ../benchmarks/plots/exp-search-vs-DSE.pdf')
