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

    print(f"Update: {np.mean(update_times)} ms")
    print("Throughput:", volume_sum/time_sum*10**9)

    return results




def plot_line(benchmarks, max_vol=100000):
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



page_size = 30
benchmarks = {}
for filename in os.listdir('../benchmarks/D1C-sparse/'):
    N = int(filename.split('_')[-2])
    benchmarks[N] = extract_query_times('../benchmarks/D1C-sparse/' + filename)

for ii in range(1, max(benchmarks[max(benchmarks.keys())])//page_size+1):
    plt.axvline(x=ii*page_size, linestyle='dashed')


plot_line(benchmarks,max_vol=100000)


#plt.yscale('log')
#plt.legend(title="N")
plt.xlabel('Query Response Volume', fontsize=12)
plt.ylabel('Query Response Time (ms)', fontsize=12)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.show()
