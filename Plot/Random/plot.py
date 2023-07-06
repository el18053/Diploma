#!/usr/bin/env python3

import re
import matplotlib.pyplot as plt
import numpy as np

# Read the data from the text
with open('data3.txt', 'r') as file:
    data = file.read()

# Extract the relevant values using regular expressions
file_sizes = re.findall(r'FILE SIZE = (\d+) KB', data)
block_sizes = re.findall(r'BLOCK SIZE = (\d+) KB', data)
cache_hit_ratios = re.findall(r'Cache Hit Ratio\(%\) : (\d+\.\d+)', data)
cache_miss_ratios = re.findall(r'Cache Miss Ratio\(%\) : (\d+\.\d+)', data)
page_cache_accesses = re.findall(r'Number page copied to user : (\d+)', data)
page_cache_misses = re.findall(r'Number page cache misses : (\d+)', data)

# Convert the extracted values to the appropriate data types
file_sizes = [int(size) for size in file_sizes]
block_sizes = [int(size) for size in block_sizes]
cache_hit_ratios = [float(ratio) for ratio in cache_hit_ratios]
cache_miss_ratios = [float(ratio) for ratio in cache_miss_ratios]
page_cache_accesses = [int(accesses) for accesses in page_cache_accesses]
page_cache_misses = [int(misses) for misses in page_cache_misses]


# Group the data based on block sizes
data_groups = {}
for i, block_size in enumerate(block_sizes):
    if block_size not in data_groups:
        data_groups[block_size] = {
            'file_sizes': [],
            'cache_hit_ratios': [],
            'cache_miss_ratios': [],
            'page_cache_accesses': [],
            'page_cache_misses': []
        }
    data_groups[block_size]['file_sizes'].append(file_sizes[i])
    data_groups[block_size]['cache_hit_ratios'].append(cache_hit_ratios[i])
    data_groups[block_size]['cache_miss_ratios'].append(cache_miss_ratios[i])
    data_groups[block_size]['page_cache_accesses'].append(page_cache_accesses[i])
    data_groups[block_size]['page_cache_misses'].append(page_cache_misses[i])

# Plotting for each block size
barWidth = 0.15
file_sizes = list(set(file_sizes)) # Get unique file sizes
file_sizes.sort()

br = []

# Plot Cache Hit Ratio
plt.figure(figsize=(20, 10))
for i, block_size in enumerate(data_groups):
    group = data_groups[block_size]
    if i == 0 : br.append(np.arange(len(file_sizes)))
    else : br.append([x + barWidth for x in br[-1]])
    plt.bar(br[-1], group['cache_hit_ratios'], width=barWidth, edgecolor='grey', label='bs=' + str(block_size))
plt.xlabel('File Size (KB)')
plt.ylabel('Ratio (%)')
plt.title('Cache Hit Ratio vs. Block Size')
plt.xticks([r + barWidth/2 for r in range(len(file_sizes))], file_sizes, rotation=45)
plt.legend()
plt.grid(True)
#plt.show()
plt.savefig(f"output/Hit_Ratio.png")

# Plot Cache Hit Ratio
plt.figure(figsize=(20, 10))
for i, block_size in enumerate(data_groups):
    group = data_groups[block_size]
    if i == 0 : br.append(np.arange(len(file_sizes)))
    else : br.append([x + barWidth for x in br[-1]])
    plt.bar(br[-1], group['page_cache_accesses'], width=barWidth, edgecolor='grey', label='bs=' + str(block_size))
plt.xlabel('File Size (KB)')
plt.ylabel('No. Accesses')
plt.title('Cache Accesses vs. Block Size')
plt.xticks([r + barWidth/2 for r in range(len(file_sizes))], file_sizes, rotation=45)
plt.legend()
plt.grid(True)
#plt.show()
plt.savefig(f"output/Cache_Accesses.png")
