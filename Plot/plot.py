#!/usr/bin/env python3

import re
import numpy as np
import matplotlib.pyplot as plt

# Read the data from the file
filename = 'data.txt'  # Replace with the actual filename
with open(filename, 'r') as file:
    data = file.read()

# Extract the relevant information using regular expressions
pattern = r"FILE SIZE = (\d+) Bytes\nNumber page accesses : (\d+)\nNumber page copied to user : (\d+)\nNumber page cache misses : (\d+)\nNumber of prefetched pages : (\d+)\nCache Hit Ratio\(\%\) : ([\d.]+)\nCache Miss Ratio\(\%\) : ([\d.]+)"
matches = re.findall(pattern, data)

# Prepare the data for plotting
file_sizes = []
page_cache_accesses = []
page_cache_misses = []

cache_hit_ratios = []
cache_miss_ratios = []

cache_prefetching_ratios = []

for match in matches:
    file_size, _, page_cache_access, page_cache_miss, _, cache_hit_ratio, cache_miss_ratio = match

    file_sizes.append(int(int(file_size) / (1024)))

    page_cache_accesses.append(int(page_cache_access))
    page_cache_misses.append(float(page_cache_miss))

    cache_hit_ratios.append(float(cache_hit_ratio))
    cache_miss_ratios.append(float(cache_miss_ratio))

# Plotting
barWidth = 0.25

br1 = np.arange(len(file_sizes))
br2 = [x + barWidth for x in br1]

#Plot Cache Hit Ratio
plt.bar(br1, cache_hit_ratios, color ='r', width = barWidth, edgecolor ='grey', label = 'Cache Hit')
plt.bar(br2, cache_miss_ratios, color ='b', width = barWidth, edgecolor ='grey', label ='Cache Miss')
plt.xlabel('File Size (KB)')
plt.ylabel('Ratio (%)')
plt.title('Cache Hit Ratio vs. File Size')
plt.xticks([r + barWidth for r in range(len(file_sizes))], file_sizes)
plt.legend()
plt.grid(True)
plt.show()

#Plot Cache Accesses
plt.bar(br1, page_cache_accesses, color ='r', width = barWidth, edgecolor ='grey', label = 'Page Cache Accesses')
plt.bar(br2, page_cache_misses, color ='b', width = barWidth, edgecolor ='grey', label ='Page Cache Misses')
plt.xlabel('File Size (KB)')
plt.ylabel('Number of Pages')
plt.title('Cache Accesses vs. File Size')
plt.xticks([r + barWidth for r in range(len(file_sizes))], file_sizes)
plt.legend()
plt.grid(True)
plt.show()
