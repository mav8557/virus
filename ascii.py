#!/usr/bin/env python3

"""
A basic script to transform any file into ascii art usable in FASM or most other assemblers
"""

import sys

if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} <file>", file=sys.stderr)
    exit(1)

with open(sys.argv[1], "r") as f:
    for line in f:
        print(";; " + line, end="")

with open(sys.argv[1], "rb") as f:
    while True:
        chunk = f.read(16)
        #print(f"db 0x{chunk[0]}, 0x{chunk[1]}, 0x{chunk[2]}, 0x{chunk[3]}, 0x{chunk[4]}, 0x{chunk[5]}")
        line = "db "
        for b in chunk:
            line += f"{hex(b)}, "
        print(line[:-2])
        if len(chunk) < 16:
            break
