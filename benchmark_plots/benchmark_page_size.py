import matplotlib.pyplot as plt
import numpy as np
import os


def extract_throughput(filename, grouping=20, skip_row=0):
    
    page_size = int(filename.split('_')[-1].split('.')[0])
    N_items = (page_size -32)//16

    volume_sum = 0
    time_sum = 0
    
    file_input = open(filename, 'r')

    for ii in range(skip_row):
        file_input.readline()

    for line in file_input.readlines():
        line = line.split(',')
        query_response_volumn = int(line[0]) // N_items * N_items
        query_response_time = int(line[1])

        volume_sum += query_response_volumn
        time_sum += query_response_time

    file_input.close()

    return volume_sum/time_sum*10**9




def plot_throughputs(S1C_throughputs, D1C_throughputs):
    xs = [ii for ii in range(len(S1C_throughputs))]
    xlabels = []
    ys = []
    zs = []
    for page_size in sorted(S1C_throughputs.keys()):
        N_items = (page_size -32)//16
        xlabels += [str(page_size) + f'({N_items})']

        ys += [S1C_throughputs[page_size]]
        zs += [D1C_throughputs[page_size]]

    plt.scatter(xs, ys, marker='o')
    plt.scatter(xs, zs, marker='x')

    plt.xticks(ticks=xs, labels=xlabels)
    plt.xlabel('Page size (bytes and #values)')
    plt.ylabel('Throughput (#values retrieved per second)')

    plt.legend(['S1C', 'D1C'])
    #plt.title('Page size vs throughput')
    
    plt.show()


S1C_throughputs = {}
for filename in os.listdir('../benchmarks/S1C-opt-p/'):
    throughput = extract_throughput('../benchmarks/S1C-opt-p/' + filename, skip_row=3)
    page_size = int(filename.split('_')[-1].split('.')[0])
    S1C_throughputs[page_size] = throughput

D1C_throughputs = {}
for filename in os.listdir('../benchmarks/D1C-opt-p/'):
    throughput = extract_throughput('../benchmarks/D1C-opt-p/' + filename, skip_row=4)
    page_size = int(filename.split('_')[-1].split('.')[0])
    D1C_throughputs[page_size] = throughput

plot_throughputs(S1C_throughputs, D1C_throughputs)
