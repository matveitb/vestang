#!/usr/bin/env python3
"""Что функция запрашивает через геттер калибровок и кого вызывает.

Паттерн обращения: ldr r0,[pc,#..] (база таблицы) + movw r1,#индекс + bl геттер.
Индекс разрешаем в адрес калибровки через таблицу.
"""
import sys, struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08000000
PCREL = re.compile(r'\[pc, #(-?(?:0x)?[0-9a-fA-F]+)\]')

def resolve(d, table_base, idx):
    ea = table_base + idx * 4
    if ea + 4 > len(d):
        return None
    p = struct.unpack_from('<I', d, ea)[0] - BASE
    if not (0 <= p + 12 <= len(d)):
        return None
    ptr = struct.unpack_from('<I', d, p + 8)[0]
    typ, width = d[p+1], struct.unpack_from('<H', d, p+2)[0]
    cnt = struct.unpack_from('<I', d, p+4)[0]
    return ptr, typ, width, cnt

def analyse(path, start, span=0x600):
    d = open(path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    regs, gets, calls, sram = {}, [], [], set()
    for ins in md.disasm(d[start:start+span], BASE + start):
        m, ops = ins.mnemonic, ins.op_str
        pm = PCREL.search(ops)
        if m == 'ldr' and pm:
            lit = ((ins.address + 4) & ~3) + int(pm.group(1), 0) - BASE
            if 0 <= lit <= len(d) - 4:
                v = struct.unpack_from('<I', d, lit)[0]
                regs[ops.split(',')[0].strip()] = v
                if 0x20000000 <= v < 0x20040000:
                    sram.add(v)
        elif m == 'movw':
            try: regs[ops.split(',')[0].strip()] = int(ops.split('#')[1], 0)
            except (ValueError, IndexError): pass
        elif m in ('movs', 'mov.w', 'mov') and '#' in ops:
            try: regs[ops.split(',')[0].strip()] = int(ops.split('#')[1], 0)
            except (ValueError, IndexError): pass
        elif m in ('bl', 'blx') and ops.startswith('#'):
            tgt = int(ops[1:], 0) - BASE
            calls.append(tgt)
            r0, r1 = regs.get('r0'), regs.get('r1')
            if r0 and BASE <= r0 < BASE + 0x100000 and isinstance(r1, int) and r1 < 0x4000:
                got = resolve(d, r0 - BASE, r1)
                if got and 0x08060000 <= got[0] < 0x08078000:
                    gets.append((r1, got, tgt))
        if m in ('pop', 'pop.w') and 'pc' in ops:
            break
        if m == 'bx' and ops.strip() == 'lr':
            break
    return gets, calls, sram

if __name__ == '__main__':
    path = sys.argv[1]
    for a in sys.argv[2:]:
        f = int(a, 16)
        gets, calls, sram = analyse(path, f)
        print(f'=== функция {f:06X} ===')
        seen = set()
        for idx, (ptr, typ, width, cnt), getter in gets:
            k = (idx, ptr)
            if k in seen: continue
            seen.add(k)
            print(f'   кал {ptr-BASE:06X}  индекс {idx:#5x}  тип{typ} разр{width} n={cnt}  геттер {getter:05X}')
        if sram:
            print(f'   SRAM: {sorted(f"{a-0x20000000:05X}" for a in sram)[:12]}')
        u = sorted(set(calls))
        print(f'   вызовы: {[f"{c:05X}" for c in u][:14]}')
