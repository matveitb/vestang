#!/usr/bin/env python3
"""Диф двух образов: группирует отличия в участки (runs) с допуском на разрывы."""
import sys

GAP = 16  # склеивать участки, если между ними меньше GAP совпадающих байт

def runs(a, b, gap=GAP):
    out, start, last = [], None, None
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            if start is None:
                start = i
            elif i - last > gap:
                out.append((start, last + 1))
                start = i
            last = i
    if start is not None:
        out.append((start, last + 1))
    return out

def load(p):
    return open(p, 'rb').read()

if __name__ == '__main__':
    a, b = load(sys.argv[1]), load(sys.argv[2])
    rs = runs(a, b)
    total = sum(e - s for s, e in rs)
    nbytes = sum(1 for i in range(len(a)) if a[i] != b[i])
    print(f'участков: {len(rs)}, покрыто {total} байт, реально отличается {nbytes}')
    for s, e in rs:
        print(f'  {s:06X}..{e:06X}  {e-s:5d}  {a[s:min(e,s+12)].hex().upper():<24} -> {b[s:min(e,s+12)].hex().upper()}')
