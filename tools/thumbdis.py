#!/usr/bin/env python3
"""Дизассемблер Thumb-2 для M74.9 (Artery AT32F4xx, база 0x08000000)
   с автоматическим разрешением PC-relative литералов.
   thumbdis.py <файл> <смещение> [длина]"""
import sys, struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08000000
PCREL = re.compile(r'\[pc, #(-?(?:0x)?[0-9a-fA-F]+)\]')

def annotate(d, ins):
    m = PCREL.search(ins.op_str)
    if not m:
        return ''
    lit = ((ins.address + 4) & ~3) + int(m.group(1), 0)
    off = lit - BASE
    if not (0 <= off <= len(d) - 4):
        return f'   ; литерал @{lit:08X} вне образа'
    v = struct.unpack_from('<I', d, off)[0]
    note = ''
    if BASE <= v < BASE + len(d):
        note = f' = flash+{v-BASE:06X}'
    elif 0x20000000 <= v < 0x20030000:
        note = f' = SRAM+{v-0x20000000:05X}'
    return f'   ; [{lit-BASE:06X}] -> {v:08X}{note}'

def disasm(path, off, ln=0x100):
    d = open(path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    for ins in md.disasm(d[off:off+ln], BASE + off):
        print(f'{ins.address-BASE:06X}  {ins.mnemonic:<8} {ins.op_str}{annotate(d, ins)}')

if __name__ == '__main__':
    a = sys.argv
    disasm(a[1], int(a[2], 0), int(a[3], 0) if len(a) > 3 else 0x100)
