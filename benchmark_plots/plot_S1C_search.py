import matplotlib.pyplot as plt
import numpy as np
import os


def extract_query_times(filename, grouping=10):
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

    plt.plot(xs, ys, label=str(N))



def max_query_volume(filename):
    file_input = open(filename, 'r')
    file_input.readline()  # M
    file_input.readline()  # N
    file_input.readline()  # setup_time

    mx = 0
    for line in file_input.readlines():
        mx = max(mx, int(line.split(',')[0]))
    file_input.close()
    return mx


page_size = 30
benchmarks = {}
for filename in os.listdir('../benchmarks/S1C-all/'):
    N = int(filename.split('_')[-1].split('.')[0])
    benchmarks[N] = extract_query_times('../benchmarks/S1C-all/' + filename)

#for ii in range(1, int(max(benchmark.keys()) / page_size)):
#    plt.axvline(x=ii*page_size, linestyle='dashed')

# Cap the x-axis at the actual max query response volume in the largest-N
# benchmark file, rather than a fixed ceiling that leaves the plot mostly empty.
biggest_n, biggest_file = max(
    (int(fn.split('_')[-1].split('.')[0]), fn) for fn in os.listdir('../benchmarks/S1C-all/')
)
max_vol = max_query_volume('../benchmarks/S1C-all/' + biggest_file)

plot_line(benchmarks, max_vol=max_vol)


#plt.yscale('log')
#plt.legend(title="N")
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.tight_layout()
os.makedirs('../benchmarks/plots/', exist_ok=True)
plt.savefig('../benchmarks/plots/exp-S1C-search.pdf')
print('Saved plot to ../benchmarks/plots/exp-S1C-search.pdf')
