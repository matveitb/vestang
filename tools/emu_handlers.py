#!/usr/bin/env python3
"""Поиск читателя блока калибровок вызовом обработчиков прерываний.

main() после инициализации крутится в пустом цикле — вся работа M74.9 идёт
в прерываниях. Поэтому: прогоняем инициализацию, снимаем снапшот RAM, затем
вызываем каждый вектор как функцию и смотрим, кто читает нужный блок.
"""
import sys, struct, collections
from unicorn import *
from unicorn.arm_const import *

BASE = 0x08000000
SRAM, SRAM_SZ = 0x20000000, 0x40000
PERIPH = [(0x40000000, 0x10000000), (0xE0000000, 0x00100000), (0x22000000, 0x02000000)]
MAGIC = 0x08FFFFF0          # адрес «возврата» — ловим завершение функции

def build(img):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(BASE, img)
    uc.mem_map(SRAM, SRAM_SZ)
    for a, s in PERIPH:
        uc.mem_map(a, s)
    uc.mem_map(MAGIC & ~0xFFF, 0x1000)
    uc.mem_write(0xE000ED88, struct.pack('<I', 0x00F00000))
    return uc

def hooks(uc, lo, hi, sink, stuck):
    def on_read(uc, access, addr, size, value, ud):
        if lo <= addr < hi:
            sink.append((uc.reg_read(UC_ARM_REG_PC), addr))
        elif addr >= 0x40000000:
            try: uc.mem_write(addr, b'\xFF' * size)
            except UcError: pass
        elif SRAM <= addr < SRAM + SRAM_SZ:
            pc = uc.reg_read(UC_ARM_REG_PC)
            if uc.mem_read(addr, size) == b'\x00' * size:
                stuck[(pc, addr)] += 1
                if stuck[(pc, addr)] > 200:
                    uc.mem_write(addr, b'\x01' + b'\x00' * (size - 1))
    def on_unmapped(uc, access, addr, size, value, ud):
        try: uc.mem_map(addr & ~0xFFFFF, 0x100000)
        except UcError: pass
        return True
    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

def main(path, lo, hi, nvec, budget):
    img = open(path, 'rb').read()
    uc = build(img)
    sink, stuck = [], collections.Counter()
    hooks(uc, lo, hi, sink, stuck)
    sp, pc = struct.unpack_from('<II', img, 0x1000)
    uc.reg_write(UC_ARM_REG_SP, sp)
    try:
        uc.emu_start(pc, BASE + 0x100000, count=3_000_000)
    except UcError:
        pass
    snap = bytes(uc.mem_read(SRAM, SRAM_SZ))
    print(f'инициализация пройдена, чтений блока за init: {len(sink)}')

    vectors = []
    for i in range(1, nvec):
        v = struct.unpack_from('<I', img, 0x1000 + 4 * i)[0]
        if BASE < v < BASE + 0x100000 and v & 1:
            vectors.append((i, v))
    uniq = sorted({v for _, v in vectors})
    print(f'уникальных обработчиков в таблице векторов: {len(uniq)}')

    found = collections.defaultdict(set)
    for h in uniq:
        uc.mem_write(SRAM, snap)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, MAGIC | 1)
        for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
            uc.reg_write(r, 0)
        sink.clear()
        try:
            uc.emu_start(h, MAGIC, count=budget)
        except UcError:
            pass
        for pc, addr in sink:
            found[h].add(addr)
    print()
    if not found:
        print('ни один обработчик блок не читает')
    for h, addrs in sorted(found.items()):
        print(f'  обработчик {h-BASE-1:06X} читает: {sorted(f"{a-BASE:06X}" for a in addrs)}')

if __name__ == '__main__':
    a = sys.argv
    main(a[1],
         BASE + int(a[2], 16) if len(a) > 2 else BASE + 0x63BD0,
         BASE + int(a[3], 16) if len(a) > 3 else BASE + 0x63C24,
         int(a[4]) if len(a) > 4 else 120,
         int(a[5]) if len(a) > 5 else 300_000)
