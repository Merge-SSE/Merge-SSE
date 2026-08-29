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

    N_updates = int(file_input.readline())
    update_times = []
    for skip in range(N_updates):
        update_times += [int(file_input.readline()) / 10**6]

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

    print(f"Update: {np.min(update_times):.2f}/{np.max(update_times):.2f}/{np.mean(update_times):.2f} ms")
    print("Throughput:", volume_sum/time_sum*10**9)

    return results




def plot_line(benchmarks, max_vol=100000):
    plt.figure(figsize=(10, 6))

    N = max(benchmarks.keys())
    data = benchmarks[N]
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

    plt.plot(xs, ys, label=str(N))

    return max(xs)



parser = argparse.ArgumentParser(description="Plot D1C search performance on sparse databases.")
parser.add_argument('-p', '--page-size', type=int, default=None, dest='page_size',
                     help="If given, draws dashed gridlines at each usable_slots boundary "
                          "(usable_slots = (page_size - 32) / 16, the query-response-volume period "
                          "at which a query gains another full-page read; see plot_S1C_zigzag.py)")
args = parser.parse_args()

benchmarks = {}
for filename in os.listdir('../benchmarks/D1C-sparse/'):
    N = int(filename.split('_')[-2])
    benchmarks[N] = extract_query_times('../benchmarks/D1C-sparse/' + filename)

plotted_max_x = plot_line(benchmarks, max_vol=100000)

# Bound gridlines to the actual plotted data range, not the max_vol ceiling: axvline
# extends matplotlib's autoscale, so drawing lines far past the real data (D1C sparse's
# actual max query volume is in the low thousands, nowhere near the 100000 ceiling)
# would stretch the x-axis and squash the real curve into a sliver near the origin.
if args.page_size:
    usable_slots = (args.page_size - 32) / 16
    ii = 1
    while ii * usable_slots <= plotted_max_x:
        plt.axvline(x=ii * usable_slots, linestyle='dashed', color='gray', linewidth=0.7)
        ii += 1

#plt.yscale('log')
#plt.legend(title="N")
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-D1C-search-sparse.pdf')
print('Saved plot to ../benchmarks/plots/exp-D1C-search-sparse.pdf')
