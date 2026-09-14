#!/usr/bin/env python3
"""Поиск диапазона [s,e), сумма которого даёт целевую КС.
Через префиксные суммы: ищем P[e]-P[s] == target (mod 2^32)."""
import sys, struct

STEP = 4

def prefix(d, width, be):
    """Префиксные суммы элементов ширины width, шаг STEP байт."""
    n = len(d) // STEP
    P = [0]*(n+1)
    if width == 1:
        acc = 0
        for i in range(n):
            acc += d[i*4] + d[i*4+1] + d[i*4+2] + d[i*4+3]
            P[i+1] = acc & 0xFFFFFFFF
    else:
        fmt = ('>' if be else '<') + ('H' if width == 2 else 'I')
        cnt = 4 // width
        acc = 0
        for i in range(n):
            for k in range(cnt):
                acc += struct.unpack_from(fmt, d, i*4 + k*width)[0]
            P[i+1] = acc & 0xFFFFFFFF
    return P

def search(d, target, width, be, label):
    P = prefix(d, width, be)
    seen = {}
    for i, v in enumerate(P):
        seen.setdefault(v, []).append(i)
    hits = []
    for j, v in enumerate(P):
        want = (v - target) & 0xFFFFFFFF
        for i in seen.get(want, []):
            if i < j:
                hits.append((i*STEP, j*STEP))
    for s, e in hits[:12]:
        print(f'  {label}: {s:06X}..{e:06X}  ({e-s} байт)')
    return hits

if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    target = int(sys.argv[2], 16)
    print(f'цель {target:08X} в {sys.argv[1]}')
    tot = 0
    for width, be, label in [(1,True,'sum8'), (2,True,'sum16be'), (2,False,'sum16le'),
                             (4,True,'sum32be'), (4,False,'sum32le')]:
        h = search(d, target, width, be, label)
        tot += len(h)
    print(f'  всего вариантов: {tot}')
