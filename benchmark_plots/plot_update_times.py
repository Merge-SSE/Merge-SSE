import matplotlib.pyplot as plt
import os


def extract_update_times_d1c(filename):
    """D1C benchmark files: 'M', 'N', 'setup_time' header lines, then an N_updates
    count followed by that many update times in nanoseconds, in the order the
    updates were performed."""
    file_input = open(filename, 'r')

    M = int(file_input.readline())
    N = int(file_input.readline())
    setup_time = int(file_input.readline()) / 10**9
    print(f"{os.path.basename(filename)}  M: {M}  N: {N}  Setup: {setup_time} s")

    N_updates = int(file_input.readline())
    times = [int(file_input.readline()) / 10**6 for _ in range(N_updates)]  # ns -> ms

    file_input.close()
    return times


def extract_update_times_dse(filename):
    """DSE-xx result files: a 'setup,time' line, then 'volume,time' search lines
    (microseconds), then 'update,time' lines in the order the updates were
    performed, ending in a trailing 'update_avg,...' line."""
    times = []

    for line in open(filename, 'r'):
        line = line.strip().split(',')
        if line[0] == 'update':
            # totalUpdateTime is a C++ double, printed in scientific notation
            # for large values by default ostream formatting.
            times.append(int(float(line[1])) / 10**3)  # us -> ms

    return times


d1c_dense_dir = '../benchmarks/D1C-dense/'
dse_dir = '../DSE-with-IO-Locality-main/'

# DSE-xx sanitizes scheme names for filenames (e.g. "SDa[1C]" -> "SDa-1C-";
# see DSE-with-IO-Locality-main/main.cpp's sanitizeForFilename call).
# L-SDd[1C] is excluded: its result file was generated with N_updates=0
# (io-dse.exe "L-SDd[1C]" SSD 0 0), so it has no update times to plot.
DSE_SCHEME_FILES = {
    'SDa[1C]': 'result_SDa-1C-_SSD_cache0_u1000.txt',
    'SDa[2C]': 'result_SDa-2C-_SSD_cache0_u1000.txt',
}

plt.figure(figsize=(10, 6))

biggest_n, biggest_file = max(
    (int(fn.split('_')[-2]), fn) for fn in os.listdir(d1c_dense_dir)
)
d1c_times = extract_update_times_d1c(d1c_dense_dir + biggest_file)
plt.scatter(range(1, len(d1c_times) + 1), d1c_times, label='D1C', s=8)

for label, fn in DSE_SCHEME_FILES.items():
    path = dse_dir + fn
    if not os.path.exists(path):
        print(f"Warning: {path} not found, skipping {label}")
        continue
    times = extract_update_times_dse(path)
    plt.scatter(range(1, len(times) + 1), times, label=label, s=8)

plt.yscale('log')
plt.legend()
plt.xlabel('Update Number', fontsize=12)
plt.ylabel('Update Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-update-vs-DSE.pdf')
print('Saved plot to ../benchmarks/plots/exp-update-vs-DSE.pdf')
