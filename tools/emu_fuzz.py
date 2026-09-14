#!/usr/bin/env python3
"""Перебор функций прошивки в поисках читателя блока калибровок.

Обработчики прерываний блок не читают — работа идёт в задачах, которые
планировщик вызывает косвенно. Поэтому вызываем каждую функцию прошивки
напрямую и смотрим, кто обращается к блоку. Хук ставится только на нужный
диапазон адресов, иначе прогон слишком медленный.
"""
import sys, struct, re, collections
from unicorn import *
from unicorn.arm_const import *

BASE = 0x08000000
SRAM, SRAM_SZ = 0x20000000, 0x40000
PERIPH = [(0x40000000, 0x10000000), (0xE0000000, 0x00100000), (0x22000000, 0x02000000)]
MAGIC = 0x08FFFFF0
CODE = [(0x1000, 0x60000), (0x80000, 0xB9F00)]

def candidates(img):
    """Начала функций: push {...,lr} (16 бит) и stmdb sp!,{...,lr} (32 бита)."""
    out = set()
    for s, e in CODE:
        for off in range(s, e - 1, 2):
            if img[off+1] == 0xB5:                          # push {..., lr}
                out.add(off)
            elif img[off] == 0x2D and img[off+1] == 0xE9:    # stmdb sp!, {...}
                if off + 3 < e and img[off+3] & 0x40:
                    out.add(off)
    return sorted(out)

def main(path, lo, hi, budget, limit):
    img = open(path, 'rb').read()
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(BASE, img)
    uc.mem_map(SRAM, SRAM_SZ)
    for a, s in PERIPH:
        uc.mem_map(a, s)
    uc.mem_map(MAGIC & ~0xFFF, 0x1000)
    uc.mem_write(0xE000ED88, struct.pack('<I', 0x00F00000))

    hits = []
    def on_block_read(uc, access, addr, size, value, ud):
        hits.append((uc.reg_read(UC_ARM_REG_PC), addr))
    def on_periph(uc, access, addr, size, value, ud):
        try: uc.mem_write(addr, b'\xFF' * size)
        except UcError: pass
    def on_unmapped(uc, access, addr, size, value, ud):
        try: uc.mem_map(addr & ~0xFFFFF, 0x100000)
        except UcError: pass
        return True
    uc.hook_add(UC_HOOK_MEM_READ, on_block_read, begin=lo, end=hi - 1)
    uc.hook_add(UC_HOOK_MEM_READ, on_periph, begin=0x40000000, end=0x4FFFFFFF)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

    sp, pc = struct.unpack_from('<II', img, 0x1000)
    uc.reg_write(UC_ARM_REG_SP, sp)
    try:
        uc.emu_start(pc, BASE + 0x100000, count=2_000_000)
    except UcError:
        pass
    snap = bytes(uc.mem_read(SRAM, SRAM_SZ))

    funcs = candidates(img)
    if limit: funcs = funcs[:limit]
    print(f'функций-кандидатов: {len(funcs)}, бюджет {budget} инструкций на каждую')
    found = collections.defaultdict(set)
    for k, f in enumerate(funcs):
        uc.mem_write(SRAM, snap)
        uc.reg_write(UC_ARM_REG_SP, sp - 0x400)
        uc.reg_write(UC_ARM_REG_LR, MAGIC | 1)
        for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
            uc.reg_write(r, 0)
        hits.clear()
        try:
            uc.emu_start(BASE + f + 1, MAGIC, count=budget)
        except UcError:
            pass
        for rpc, addr in hits:
            found[f].add(addr)
        if k % 400 == 0:
            print(f'   ... {k}/{len(funcs)}, нашлось {len(found)}', flush=True)
    print()
    for f, addrs in sorted(found.items()):
        print(f'  функция {f:06X} читает: {sorted(f"{a-BASE:06X}" for a in addrs)}')
    print(f'итого функций, читающих блок: {len(found)}')

if __name__ == '__main__':
    a = sys.argv
    main(a[1], BASE + int(a[2], 16), BASE + int(a[3], 16),
         int(a[4]) if len(a) > 4 else 30_000,
         int(a[5]) if len(a) > 5 else 0)
