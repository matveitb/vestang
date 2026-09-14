#!/usr/bin/env python3
"""Эмуляция старта M74.9 (Artery AT32F4xx, Cortex-M4) для поиска читателей калибровок.

Блок конфигурации круиза не адресуется кодом напрямую, поэтому ищем его
читателя динамически: прогоняем инициализацию и логируем, какой PC читает
байты блока и куда они уезжают в RAM.

    emu.py <файл> [начало-блока] [конец-блока] [лимит-инструкций]
"""
import sys, struct, collections
from unicorn import *
from unicorn.arm_const import *

BASE = 0x08000000
SRAM, SRAM_SZ = 0x20000000, 0x40000
# 0x42000000 (bitband периферии) лежит внутри первого региона, отдельно не мапим
PERIPH = [(0x40000000, 0x10000000), (0xE0000000, 0x00100000),
          (0x22000000, 0x02000000)]

def run(path, lo, hi, limit):
    img = open(path, 'rb').read()
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(BASE, img)
    uc.mem_map(SRAM, SRAM_SZ)
    for a, s in PERIPH:
        uc.mem_map(a, s)
    uc.mem_write(0xE000ED88, struct.pack('<I', 0x00F00000))   # CPACR: включить FPU

    stuck = collections.Counter()      # (PC, адрес) -> сколько раз прочитан нулевой флаг
    reads = collections.Counter()      # PC -> сколько раз читал блок
    detail = {}                        # (PC, адрес) -> мнемоника
    shadow = {}                        # значение из блока -> куда записали в RAM
    last_read = {}

    def on_read(uc, access, addr, size, value, ud):
        if lo <= addr < hi:
            pc = uc.reg_read(UC_ARM_REG_PC)
            reads[pc] += 1
            detail[(pc, addr)] = size
            last_read[pc] = addr
        # периферия: отдаём все единицы, иначе старт зависает на флагах готовности
        elif addr >= 0x40000000:
            try: uc.mem_write(addr, b'\xFF' * size)
            except UcError: pass
        # флаги, которые в железе ставит прерывание: если код долго крутится на
        # нулевом значении, подставляем 1 — иначе инициализация не идёт дальше
        elif SRAM <= addr < SRAM + SRAM_SZ:
            pc = uc.reg_read(UC_ARM_REG_PC)
            if uc.mem_read(addr, size) == b'\x00' * size:
                stuck[(pc, addr)] += 1
                if stuck[(pc, addr)] > 200:
                    uc.mem_write(addr, b'\x01' + b'\x00' * (size - 1))

    def on_write(uc, access, addr, size, value, ud):
        if SRAM <= addr < SRAM + SRAM_SZ:
            pc = uc.reg_read(UC_ARM_REG_PC)
            if pc in last_read:
                shadow.setdefault((pc, last_read[pc]), addr)

    def on_unmapped(uc, access, addr, size, value, ud):
        try: uc.mem_map(addr & ~0xFFFFF, 0x100000)
        except UcError: pass
        return True

    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

    sp, pc = struct.unpack_from('<II', img, 0x1000)
    uc.reg_write(UC_ARM_REG_SP, sp)
    err = None
    try:
        uc.emu_start(pc, BASE + 0x100000, count=limit)
    except UcError as e:
        err = e
    return reads, detail, shadow, err, uc

if __name__ == '__main__':
    path = sys.argv[1]
    lo = BASE + int(sys.argv[2], 16) if len(sys.argv) > 2 else BASE + 0x63BD0
    hi = BASE + int(sys.argv[3], 16) if len(sys.argv) > 3 else BASE + 0x63C24
    limit = int(sys.argv[4]) if len(sys.argv) > 4 else 20_000_000
    reads, detail, shadow, err, uc = run(path, lo, hi, limit)
    print(f'PC после прогона: {uc.reg_read(UC_ARM_REG_PC):08X}   ошибка: {err}')
    print(f'обращений к блоку {lo-BASE:06X}..{hi-BASE:06X}: {sum(reads.values())} с {len(reads)} мест')
    for pc, n in reads.most_common(30):
        addrs = sorted({a for (p, a) in detail if p == pc})
        print(f'   PC {pc-BASE:06X} x{n:<5} читает: {[f"{a-BASE:06X}" for a in addrs][:8]}')
    if shadow:
        print('теневые копии в RAM:')
        for (pc, a), dst in list(shadow.items())[:20]:
            print(f'   кал {a-BASE:06X} (PC {pc-BASE:06X}) -> SRAM {dst:08X}')
