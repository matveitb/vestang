#!/usr/bin/env python3
"""Поиск обращений к калибровке в коде M74.9.

Прямых литералов на адрес калибровки в прошивке нет — код грузит базу
(через literal pool или movw/movt) и обращается по смещению. Сканер ведёт
状 значения регистров на коротком окне и ловит доступ base+imm.

    xref.py <файл> <адрес-калибровки> [ещё адреса...]
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08000000
SEGMENTS = [(0x1000, 0x60000), (0x80000, 0xB9F00)]
ACCESS = ('ldrb', 'ldrh', 'ldr', 'strb', 'strh', 'str', 'ldrsb', 'ldrsh')

def scan(path, targets):
    d = open(path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    hits = []
    for seg_s, seg_e in SEGMENTS:
        pos = seg_s
        while pos < seg_e:
            regs, pend = {}, {}
            n = 0
            for ins in md.disasm(d[pos:seg_e], BASE + pos):
                n += 1
                m, ops = ins.mnemonic, ins.op_str
                try:
                    if m == 'ldr' and '[pc,' in ops:
                        rd = ops.split(',')[0].strip()
                        imm = int(ops.split('#')[1].rstrip(']'), 0)
                        lit = ((ins.address + 4) & ~3) + imm - BASE
                        if 0 <= lit <= len(d) - 4:
                            regs[rd] = struct.unpack_from('<I', d, lit)[0]
                    elif m == 'movw':
                        rd, v = ops.split(',')[0].strip(), int(ops.split('#')[1], 0)
                        pend[rd] = v; regs[rd] = v
                    elif m == 'movt':
                        rd, v = ops.split(',')[0].strip(), int(ops.split('#')[1], 0)
                        regs[rd] = (pend.get(rd, regs.get(rd, 0)) & 0xFFFF) | (v << 16)
                    elif m in ('add', 'add.w', 'adds', 'addw') and '#' in ops:
                        f = [x.strip() for x in ops.split(',')]
                        rd, rs = f[0], (f[1] if len(f) > 2 else f[0])
                        if rs in regs:
                            regs[rd] = regs[rs] + int(f[-1].lstrip('#'), 0)
                    elif m in ('mov', 'mov.w') and '#' not in ops:
                        f = [x.strip() for x in ops.split(',')]
                        if len(f) == 2 and f[1] in regs:
                            regs[f[0]] = regs[f[1]]
                    elif m in ACCESS and '[' in ops:
                        inner = ops[ops.index('[') + 1:ops.index(']')]
                        parts = [p.strip() for p in inner.split(',')]
                        rb = parts[0]
                        off = int(parts[1].lstrip('#'), 0) if len(parts) > 1 and parts[1].startswith('#') else 0
                        if rb in regs:
                            a = regs[rb] + off
                            if a in targets:
                                hits.append((ins.address - BASE, m, ops, a))
                except (ValueError, IndexError):
                    pass
                if n % 4000 == 0:
                    regs, pend = {}, {}      # периодический сброс окна
            # линейная развёртка сорвалась на данных — сдвигаемся и продолжаем
            adv = max(2, (ins.address - BASE - pos + ins.size) if n else 2)
            pos += adv
    return hits

if __name__ == '__main__':
    tg = {BASE + int(a, 16) for a in sys.argv[2:]}
    for off, m, ops, a in scan(sys.argv[1], tg):
        print(f'  {off:06X}  {m:6} {ops:<28} -> кал {a-BASE:06X}')
