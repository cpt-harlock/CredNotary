#!/usr/bin/env python3
"""Summarizes a bench.sh log: median ns/op per (config, op), standard deviation
and ratio to the baseline."""
import re
import statistics
import sys
from collections import defaultdict

pat = re.compile(r'^CFG=(\S+) BENCH op=(\S+) n=\d+ ns_per_op=(\d+)')
data = defaultdict(list)
for line in open(sys.argv[1]):
    m = pat.match(line)
    if m:
        data[(m[1], m[2])].append(int(m[3]))

cfgs = [c for c in ['base', 'crednotary-block'] if (c, 'null') in data]
ops = ['null', 'open', 'stat', 'setuid', 'fork', 'exec']
print(f"{'op':8}" + ''.join(f"{c:>22}" for c in cfgs))
for op in ops:
    base = statistics.median(data[('base', op)])
    row = f"{op:8}"
    for c in cfgs:
        v = data[(c, op)]
        med = statistics.median(v)
        sd = statistics.stdev(v) if len(v) > 1 else 0
        row += f"{med:>10.0f}±{sd:<5.0f}{med / base:>5.2f}x "
    print(row)
