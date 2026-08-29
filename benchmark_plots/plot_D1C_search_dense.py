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



def max_query_volume(filename):
    file_input = open(filename, 'r')
    file_input.readline()  # M
    file_input.readline()  # N
    file_input.readline()  # setup_time
    N_updates = int(file_input.readline())
    for skip in range(N_updates):
        file_input.readline()

    mx = 0
    for line in file_input.readlines():
        mx = max(mx, int(line.split(',')[0]))
    file_input.close()
    return mx


parser = argparse.ArgumentParser(description="Plot D1C search performance on dense databases.")
args = parser.parse_args()

benchmarks = {}
for filename in os.listdir('../benchmarks/D1C-dense/'):
    N = int(filename.split('_')[-2])
    benchmarks[N] = extract_query_times('../benchmarks/D1C-dense/' + filename)

# Cap the x-axis at the actual max query response volume in the largest-N
# benchmark file, rather than a fixed ceiling that leaves the plot mostly empty.
biggest_n, biggest_file = max(
    (int(fn.split('_')[-2]), fn) for fn in os.listdir('../benchmarks/D1C-dense/')
)
max_vol = max_query_volume('../benchmarks/D1C-dense/' + biggest_file)

plot_line(benchmarks, max_vol=max_vol)

#plt.yscale('log')
#plt.legend(title="N")
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-D1C-search-dense.pdf')
print('Saved plot to ../benchmarks/plots/exp-D1C-search-dense.pdf')
