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
    for N in sorted(benchmarks.keys()):
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
        
        plt.plot(xs, ys, label=str(N))



parser = argparse.ArgumentParser(description="Plot S1C search performance zig-zag up to a small query response volume.")
parser.add_argument('-p', '--page-size', type=int, default=1024, dest='page_size',
                     help="Page size in bytes; draws dashed gridlines at each usable_slots boundary "
                          "(usable_slots = (page_size - 32) / 16), where the zig-zag period comes from.")
args = parser.parse_args()

benchmarks = {}
for filename in os.listdir('../benchmarks/S1C-all/'):
    N = int(filename.split('_')[-1].split('.')[0])
    benchmarks[N] = extract_query_times('../benchmarks/S1C-all/' + filename)


max_vol = 300
plot_lines(benchmarks, max_vol=max_vol)

usable_slots = (args.page_size - 32) / 16
ii = 1
while ii * usable_slots <= max_vol:
    plt.axvline(x=ii * usable_slots, linestyle='dashed', color='gray', linewidth=0.7)
    ii += 1

plt.legend(title="N")
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-S1C-zigzag.pdf')
print('Saved plot to ../benchmarks/plots/exp-S1C-zigzag.pdf')
