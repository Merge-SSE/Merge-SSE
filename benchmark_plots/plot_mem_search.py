import argparse
import matplotlib.pyplot as plt
import numpy as np
import os


def extract_query_times(filename, grouping=5):
    results = {}

    volume_sum = 0
    time_sum = 0
    
    file_input = open(filename, 'r')

    M = int(file_input.readline())
    N = int(file_input.readline())
    setup_time = int(file_input.readline()) / 10**9
    print(f"M: {M}")
    print(f"N: {N}")
    print(f"Setup: {setup_time} s")

    N_updates = file_input.readline()
    if ',' not in N_updates:
        for skip in range(int(N_updates)):
            file_input.readline()

    for line in file_input.readlines():
        line = line.split(',')
        query_response_volumn = int(line[0])
        query_response_time = int(line[1])

        volume_sum += query_response_volumn
        time_sum += query_response_time

        x = ((query_response_volumn // grouping) + 1) * grouping
        y = query_response_time / 10**6

        if x not in results:
            results[x] = []
        results[x].append(y)

    file_input.close()

    print("Throughput:", volume_sum/time_sum*10**9)
    return results




def plot_lines(benchmarks, max_vol=100000):
    all_ys = []
    for label in sorted(benchmarks.keys()):
        data = benchmarks[label]
        zs = sorted(list(data.keys()))

        xs = []
        for x in zs:
            if x <= max_vol:
                xs += [x]

        ys = []
        for x in xs:
            values = sorted(data[x])
            ys += [np.mean(values)]

        print(max(xs), max(ys))

        plt.plot(xs, ys, label=label)
        all_ys += ys

    return all_ys


parser = argparse.ArgumentParser(description="Plot search performance of the in-memory benchmarks.")
parser.add_argument('-p', '--page-size', type=int, default=None, dest='page_size',
                     help="If given, draws dashed gridlines at each usable_slots boundary "
                          "(usable_slots = (page_size - 32) / 16, the query-response-volume period "
                          "at which a query gains another full-page read; see plot_S1C_zigzag.py)")
parser.add_argument('--max-vol', type=int, default=300, help="Max query response volume to plot (default: 300)")
args = parser.parse_args()

# D1C labels are annotated dense/sparse from the filename suffix (D1C.exe always writes
# "..._dense.txt"/"..._sparse.txt" regardless of in-memory mode).
benchmarks = {}
for filename in os.listdir('../benchmarks/mem-results/'):
    parts = filename.split('_')
    label = parts[0]
    if parts[0] == 'D1C':
        label += ' (dense)' if filename.endswith('_dense.txt') else ' (sparse)'
    benchmarks[label] = extract_query_times('../benchmarks/mem-results/' + filename)


plt.figure(figsize=(10, 6))
all_ys = plot_lines(benchmarks, max_vol=args.max_vol)

if all_ys:
    y_min, y_max = min(all_ys), max(all_ys)
    padding = max((y_max - y_min) * 0.1, 0.05)
    plt.ylim(max(0, y_min - padding), y_max + padding)

if args.page_size:
    usable_slots = (args.page_size - 32) / 16
    ii = 1
    while ii * usable_slots <= args.max_vol:
        plt.axvline(x=ii * usable_slots, linestyle='dashed', color='gray', linewidth=0.7)
        ii += 1

plt.legend()
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=11)
plt.yticks(fontsize=11)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-mem.pdf')
print('Saved plot to ../benchmarks/plots/exp-mem.pdf')
