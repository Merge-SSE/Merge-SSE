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
        
        ax1.plot(xs, ys, label=label)
        ax2.plot(xs, ys, label=label)



page_size = 30
benchmarks = {}
for filename in os.listdir('../benchmarks/mem-results/'):
    parts = filename.split('_')
    label = parts[0]
    if parts[0] == 'D1C':
        M = int(parts[2])
        N = int(parts[3])
        if N < page_size * M:
            label += ' (N < pM)'
        else:
            label += ' (N >= pM)'
    benchmarks[label] = extract_query_times('../benchmarks/mem-results/' + filename)



fig, (ax1, ax2) = plt.subplots(2, 1, sharex=True)
fig.subplots_adjust(hspace=0.15)

ax1.set_ylim(2.3, 2.8)
ax2.set_ylim(0, 0.5)

# hide the spines between ax and ax2
ax1.spines.bottom.set_visible(False)
ax2.spines.top.set_visible(False)
ax1.xaxis.tick_top()
ax1.tick_params(labeltop=False)  # don't put tick labels at the top
ax2.xaxis.tick_bottom()
    
plot_lines(benchmarks,max_vol=300)

for ii in range(1, 300//page_size+1):
    ax1.axvline(x=ii*page_size, linestyle='dashed')
    ax2.axvline(x=ii*page_size, linestyle='dashed')



#plt.yscale('log')
plt.legend()
plt.xlabel('Query Response Volume', fontsize=12)
fig.supylabel('Query Response Time (ms)', fontsize=12)

ax1.tick_params(labelsize=11)
ax2.tick_params(labelsize=11)
plt.yticks(fontsize=11)

plt.show()
