#!/usr/bin/env python3
"""Граф вызовов прошивки M74.9: кто кого вызывает.

Линейная развёртка Thumb даёт ложные инструкции в данных, поэтому цель bl
принимается только если по ней стоит пролог функции (push {...,lr} или
stmdb sp!,{...,lr}).
"""
import sys, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08000000
CODE = [(0x1000, 0x60000), (0x80000, 0xB9F00)]

def is_prologue(d, off):
    if off < 0 or off + 4 > len(d):
        return False
    return d[off+1] == 0xB5 or (d[off] == 0x2D and d[off+1] == 0xE9 and d[off+3] & 0x40)

def build(path):
    d = open(path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    callers = collections.defaultdict(set)
    callees = collections.defaultdict(set)
    cur = None
    for s, e in CODE:
        pos = s
        while pos < e:
            last = pos
            for ins in md.disasm(d[pos:e], BASE + pos):
                off = ins.address - BASE
                last = off + ins.size
                if is_prologue(d, off):
                    cur = off
                if ins.mnemonic == 'bl' and ins.op_str.startswith('#') and cur is not None:
                    try: tgt = int(ins.op_str[1:], 0) - BASE
                    except ValueError: continue
                    if is_prologue(d, tgt):
                        callers[tgt].add(cur)
                        callees[cur].add(tgt)
            # развёртка сорвалась на данных — сдвигаемся и продолжаем
            pos = max(last, pos + 2)
    return callers, callees

if __name__ == '__main__':
    callers, callees = build(sys.argv[1])
    for a in sys.argv[2:]:
        f = int(a, 16)
        print(f'=== {f:06X} ===')
        print(f'   вызывают её: {sorted(f"{x:06X}" for x in callers.get(f, []))[:12]}')
        print(f'   вызывает:    {sorted(f"{x:06X}" for x in callees.get(f, []))[:14]}')
