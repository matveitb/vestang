#!/usr/bin/env python3
"""Карта непустых регионов образа (что не залито 0xFF)."""
import sys

BLK = 0x100

def regions(path, blk=BLK):
    data = open(path, 'rb').read()
    out, start = [], None
    for off in range(0, len(data), blk):
        empty = all(b == 0xFF for b in data[off:off+blk])
        if not empty and start is None:
            start = off
        elif empty and start is not None:
            out.append((start, off))
            start = None
    if start is not None:
        out.append((start, len(data)))
    return out, data

if __name__ == '__main__':
    for p in sys.argv[1:]:
        rs, data = regions(p)
        used = sum(e - s for s, e in rs)
        print(f'{p}  занято {used} / {len(data)} ({100*used/len(data):.1f}%)')
        for s, e in rs:
            print(f'   {s:06X}..{e:06X}  {e-s:7d}')
