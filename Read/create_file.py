#!/usr/bin/env python3


import os

file_size = 1024 * 1024  # 1 MB
file_path = 'output.txt'

with open(file_path, 'wb') as file:
    file.write(os.urandom(file_size))

print(f"File '{file_path}' created with size {file_size} bytes.")
