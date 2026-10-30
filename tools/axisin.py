#!/usr/bin/env python3
"""Откуда оси калибровок берут вход: переменная RAM на каждый вызов поиска по оси.

Поиск точки на оси — функции (BB04) 0x49C8 / 0x4A2C / 0x4A8C / 0x4AF4 / 0x5030:
    r0 = таблица дескрипторов, r1 = индекс оси, r2 = входное значение, r3 = флаг
Дескриптор хранит только копию входа (+0xC), источник виден лишь в вызывающем
коде. Для каждого `bl` в эти функции прогоняем вызывающую функцию от пролога
до вызова с простым отслеживанием регистров: константа / значение из памяти
по известному адресу / неизвестно.

    axisin.py <файл.bin> [--csv выход]      ось -> источники
"""
import sys, re, struct
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x08000000
CODE = [(0x1000, 0x41000), (0x80000, 0xBA000)]
LOAD = re.compile(r'^ldr(s?)(b|h)?(\.w)?$')

def axis_funcs(d):
    """Функции поиска по оси: ldr.w rX,[r0,r1,lsl#2], затем ldrh rY,[rX,#0xa] (n-1)."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    out = set()
    for off in range(0x1000, 0x41000, 2):
        if d[off] != 0x50 or d[off + 1] != 0xF8 or d[off + 2] != 0x21:
            continue
        ins = list(md.disasm(d[off:off + 16], BASE + off, 3))
        if not ins or not ins[0].op_str.endswith('[r0, r1, lsl #2]'):
            continue
        reg = ins[0].op_str.split(',')[0]
        if any(i.mnemonic.startswith('ldrh') and i.op_str.endswith(f'[{reg}, #0xa]') for i in ins[1:]):
            for back in range(2, 12, 2):
                p = off - back
                if d[p + 1] == 0xB5 or (d[p] == 0x2D and d[p + 1] == 0xE9):
                    out.add(p)
                    break
    return sorted(out)

def func_start(d, pc):
    for back in range(2, 0x600, 2):
        p = pc - back
        if d[p + 1] == 0xB5 or (d[p] == 0x2D and d[p + 1] == 0xE9 and d[p + 3] & 0x40):
            return p
    return max(pc - 0x200, 0x1000)

def lit(d, ins):
    m = re.search(r'\[pc, #(-?(?:0x)?[0-9a-f]+)\]', ins.op_str)
    a = ((ins.address + 4) & ~3) + int(m.group(1), 0) - BASE
    return struct.unpack_from('<I', d, a)[0] if 0 <= a <= len(d) - 4 else None

def simulate(d, md, start, end):
    """Состояние регистров на адресе end (линейно от start).
    ('c', v) константа, ('m', адрес, ширина, знак) значение из памяти,
    ('x', pc) значение, вычисленное инструкцией по адресу pc,
    ('s', смещение) значение со стека (аргумент вызывающего),
    ('p', k) параметр rk функции, не перезаписанный до end.
    Второе возвращаемое — что записано в слоты стека [sp, #k] (для аргументов вызова)."""
    regs = {f'r{k}': ('p', k) for k in range(4)}
    stack = {}
    for ins in md.disasm(d[start:end], BASE + start):
        m, ops = ins.mnemonic, ins.op_str
        parts = [p.strip() for p in ops.split(',')]
        dst = parts[0] if parts else ''
        here = ('x', ins.address - BASE)
        if m in ('bl', 'blx'):
            for r in ('r0', 'r1', 'r2', 'r3', 'ip', 'lr'):
                regs[r] = ('x', ins.address - BASE)
            regs['r0'] = ('ret', ins.address - BASE)
            continue
        if m.startswith('str') and '[sp' in ops:
            mm = re.search(r'\[sp(?:, #(-?(?:0x)?[0-9a-f]+))?\]', ops)
            if mm:
                stack[int(mm.group(1), 0) if mm.group(1) else 0] = regs.get(dst, here)
            continue
        if m.startswith(('str', 'cmp', 'tst', 'b', 'cb', 'it', 'push', 'pop', 'nop', 'teq', 'cmn', 'vst', 'vpush')) \
                and not m.startswith(('bic', 'bfi', 'bfc')):
            continue
        if '[pc' in ops and m.startswith('ldr'):
            regs[dst] = ('c', lit(d, ins))
            continue
        lm = LOAD.match(m)
        if lm and '[' in ops:
            mm = re.search(r'\[(\w+)(?:, #(-?(?:0x)?[0-9a-f]+))?\]', ops)
            base = regs.get(mm.group(1)) if mm else None
            off = int(mm.group(2), 0) if mm and mm.group(2) else 0
            w = {'b': 1, 'h': 2, None: 4}[lm.group(2)]
            if mm and mm.group(1) == 'sp':
                regs[dst] = ('s', off)
            elif base and base[0] == 'c' and base[1] is not None:
                regs[dst] = ('m', base[1] + off, w, bool(lm.group(1)))
            else:
                regs[dst] = here
            continue
        if m in ('movw', 'movs', 'mov', 'mov.w', 'mvn', 'mvns') and '#' in ops and len(parts) == 2:
            try:
                v = int(parts[1].lstrip('#'), 0) & 0xFFFFFFFF
                regs[dst] = ('c', (~v & 0xFFFFFFFF) if m.startswith('mvn') else v)
            except ValueError:
                regs[dst] = here
            continue
        if m == 'movt' and regs.get(dst, ('',))[0] == 'c':
            regs[dst] = ('c', (regs[dst][1] & 0xFFFF) | (int(parts[1].lstrip('#'), 0) << 16))
            continue
        if m in ('add', 'adds', 'add.w', 'addw') and parts[-1].startswith('#'):
            src = regs.get(parts[1] if len(parts) == 3 else dst)
            if src and src[0] == 'c' and src[1] is not None:
                regs[dst] = ('c', (src[1] + int(parts[-1].lstrip('#'), 0)) & 0xFFFFFFFF)
            else:
                regs[dst] = here
            continue
        if m in ('mov', 'movs') and len(parts) == 2 and parts[1] in regs:
            regs[dst] = regs[parts[1]]
            continue
        if m in ('sxth', 'uxth', 'sxtb', 'uxtb', 'sxth.w', 'uxth.w', 'sxtb.w', 'uxtb.w') and len(parts) == 2:
            regs[dst] = regs.get(parts[1], here)
            continue
        if dst:
            regs[dst] = here
    return regs, stack

def frame_size(d, md, start):
    """Размер кадра после пролога: push + sub sp, #imm."""
    size = 0
    for ins in md.disasm(d[start:start + 16], BASE + start, 3):
        if ins.mnemonic in ('push', 'push.w', 'stmdb'):
            size += 4 * len(ins.op_str.split('{')[1].split(','))
        elif ins.mnemonic in ('sub', 'sub.w', 'subw') and ins.op_str.startswith('sp, sp, #') or ins.op_str.startswith('sp, #'):
            if ins.mnemonic.startswith('sub'):
                size += int(ins.op_str.split('#')[1], 0)
    return size

def all_calls(d):
    """цель -> список адресов bl."""
    calls = defaultdict(list)
    for s, e in CODE:
        for pc in range(s, e - 4, 2):
            h1, h2 = struct.unpack_from('<HH', d, pc)
            if (h1 & 0xF800) != 0xF000 or (h2 & 0xD000) != 0xD000:
                continue
            S = (h1 >> 10) & 1
            off = (S << 24) | ((1 - (((h2 >> 13) & 1) ^ S)) << 23) | ((1 - (((h2 >> 11) & 1) ^ S)) << 22) \
                | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
            if S:
                off -= 1 << 25
            calls[pc + 4 + off].append(pc)
    return calls

def resolve(d, md, calls, func, val, depth=3):
    """Параметр функции ('p', k) или аргумент со стека ('s', off) -> источники у вызывающих."""
    out = Counter()
    if depth == 0:
        return out
    fs = frame_size(d, md, func) if val[0] == 's' else 0
    for site in calls.get(func, []):
        st = func_start(d, site)
        regs, stack = simulate(d, md, st, site)
        v = regs.get(f'r{val[1]}') if val[0] == 'p' else stack.get(val[1] - fs)
        if v and v[0] in ('p', 's'):
            out.update(resolve(d, md, calls, st, v, depth - 1))
        else:
            out[describe(d, func_start(d, site), v)] += 1
    return out

def describe(d, fstart, v):
    if v and v[0] == 'm' and 0x20000000 <= v[1] < 0x20040000:
        return f'RAM {v[1] - 0x20000000:05X}/{v[2]}{"s" if v[3] else "u"}'
    if v and v[0] == 'c':
        return f'конст {v[1]}'
    if v and v[0] in ('x', 'ret'):
        return f'выч@{v[1]:05X}'
    return '?'

def analyse(path):
    d = open(path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    funcs = set(axis_funcs(d))
    calls = all_calls(d)
    res = defaultdict(Counter)
    # перебор всех bl: декодируем пары полуслов
    for s, e in CODE:
        for pc in range(s, e - 4, 2):
            h1, h2 = struct.unpack_from('<HH', d, pc)
            if (h1 & 0xF800) != 0xF000 or (h2 & 0xD000) != 0xD000:
                continue
            S = (h1 >> 10) & 1
            off = (S << 24) | ((1 - (((h2 >> 13) & 1) ^ S)) << 23) | ((1 - (((h2 >> 11) & 1) ^ S)) << 22) \
                | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
            if S:
                off -= 1 << 25
            tgt = pc + 4 + off
            if tgt not in funcs:
                continue
            fst = func_start(d, pc)
            regs, _ = simulate(d, md, fst, pc)
            r1, r2 = regs.get('r1'), regs.get('r2')
            if not r1 or r1[0] != 'c':
                continue
            if r2 and r2[0] in ('p', 's'):
                for src, n in resolve(d, md, calls, fst, r2).items():
                    res[r1[1]][('арг: ' + src, tgt)] += n
            else:
                res[r1[1]][(describe(d, fst, r2), tgt)] += 1
    return res, funcs

if __name__ == '__main__':
    res, funcs = analyse(sys.argv[1])
    print('функции поиска по оси:', ' '.join(f'{f:05X}' for f in sorted(funcs)))
    known = sum(1 for a in res for (s, _), n in res[a].items() if s != '?')
    print(f'осей с вызовами: {len(res)}')
    rows = []
    for a in sorted(res):
        srcs = Counter()
        for (s, _), n in res[a].items():
            srcs[s] += n
        rows.append((a, srcs))
        print(f'  #{a:03X}: ' + ', '.join(f'{s} x{n}' for s, n in srcs.most_common()))
    if '--csv' in sys.argv:
        with open(sys.argv[sys.argv.index('--csv') + 1], 'w') as f:
            for a, srcs in rows:
                for s, n in srcs.items():
                    f.write(f'{a:03X};{s};{n}\n')
