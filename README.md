# Diploma
# Optimizing Linux Kernel Storage Stack with eBPF

## Description

This project investigates the performance limitations introduced by the Linux kernel storage stack in the era of high-performance storage technologies, such as ultralow latency SSDs and NVMe devices. As storage speeds increase, the kernel's relative overhead becomes a bottleneck, particularly in file operations. The focus is on reexamining the kernel's Page Cache and its mechanisms, including prefetching through Read-Ahead, to improve system performance and adaptability.

The culmination of this work is a custom tool leveraging **eBPF (Extended Berkeley Packet Filter)**, enabling users to define custom Page Cache data-fetching patterns, tailored to their application requirements. This tool enhances the efficiency of the kernel’s storage stack by optimizing data placement and access strategies.

## Features

- **Analysis of the Page Cache**: Evaluation of its role in sequential and complex access patterns.
- **Custom Read-Ahead Mechanism**: Development of a tool utilizing eBPF to customize data prefetching behavior.
- **Performance Benchmarking**: Synthetic benchmarks with **FIO** for `read()` and `mmap()` operations.
- **Real-World Application**: Demonstration of the tool's benefits in Firecracker's snapshotting process.

## Technologies

- **Linux Kernel**: Analysis and modification of storage stack components.
- **eBPF**: Advanced kernel-level scripting for customizable Page Cache behavior.
- **FIO Benchmarking**: Performance evaluation of `read()` and `mmap()` operations.
