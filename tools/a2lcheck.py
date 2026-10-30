#!/usr/bin/env python3
"""Проверка A2L от mka2l.py против бинарника: синтаксис, ссылки, и что
каждая CHARACTERISTIC / AXIS_PTS читает ровно те байты и значения, которые
описывает таблица дескрипторов (tools/calmap.py).

    a2lcheck.py <файл.a2l> <файл.bin>
"""
import sys, re, struct
from calmap import load, BASE, ETYPE

FMT = {'UBYTE': 'B', 'SBYTE': 'b', 'UWORD': 'H', 'SWORD': 'h', 'ULONG': 'I', 'SLONG': 'i'}

def blocks(text, kind):
    return re.findall(rf'/begin {kind} (\S+)(.*?)/end {kind}', text, re.S)

def main(a2l, binf):
    t = open(a2l, encoding='utf-8').read()
    errs = []
    opens = re.findall(r'/begin (\w+)', t); closes = re.findall(r'/end (\w+)', t)
    if sorted(opens) != sorted(closes):
        errs.append('несбалансированные /begin /end')
    names = [n for k in ('CHARACTERISTIC', 'AXIS_PTS', 'MEASUREMENT') for n, _ in blocks(t, k)]
    if len(names) != len(set(names)):
        errs.append('повторяющиеся имена')
    layouts = {n: b for n, b in blocks(t, 'RECORD_LAYOUT')}
    cms = {n for n, _ in blocks(t, 'COMPU_METHOD')}
    meas = {n for n, _ in blocks(t, 'MEASUREMENT')}
    axes = {}
    for n, b in blocks(t, 'AXIS_PTS'):
        f = b.split('"', 2)[2].split()
        addr, inp, rl, _, cm, cnt = int(f[0], 16), f[1], f[2], f[3], f[4], int(f[5])
        if rl not in layouts or cm not in cms or (inp != 'NO_INPUT_QUANTITY' and inp not in meas):
            errs.append(f'{n}: битая ссылка')
        typ = layouts[rl].split()[2]
        axes[n] = (addr, typ, cnt)
    d, _, objs, _ = load(binf)
    want = {}
    for o in objs:
        if o.data is not None and o.in_cal():
            want.update({BASE + o.data + i * ETYPE[o.etype][1]: None for i in range(o.n)})
    covered = set()
    def read(addr, typ, n):
        sz = struct.calcsize(FMT[typ])
        for i in range(n * sz):
            if addr + i in covered:
                errs.append(f'перекрытие @{addr + i:08X}')
            covered.add(addr + i)
        return list(struct.unpack_from('<%d%s' % (n, FMT[typ]), d, addr - BASE))
    by_addr = {BASE + o.data: o for o in objs if o.data is not None and o.in_cal()}
    for n, (addr, typ, cnt) in axes.items():
        o = by_addr.get(addr)
        v = read(addr, typ, cnt)
        uns = o is not None and ETYPE[o.etype][0][0] == 'u'
        raw = [x & 0xFFFF if typ == 'SWORD' and uns else x for x in v]
        if o is None or o.what != 'ось' or raw != o.values(d):
            errs.append(f'{n}: значения не совпадают с дескриптором')
    nchar = 0
    for n, b in blocks(t, 'CHARACTERISTIC'):
        f = b.split('"', 2)[2].split()
        kind, addr, rl, cm = f[0], int(f[1], 16), f[2], f[4]
        if rl not in layouts or cm not in cms:
            errs.append(f'{n}: битая ссылка')
        typ = layouts[rl].split()[2]
        if kind == 'VALUE':
            cnt = 1
        elif kind == 'VAL_BLK':
            cnt = int(re.search(r'MATRIX_DIM (\d+)', b).group(1))
        else:
            refs = re.findall(r'AXIS_PTS_REF (\S+)', b)
            if any(r not in axes for r in refs):
                errs.append(f'{n}: нет оси'); continue
            cnt = 1
            for r in refs:
                cnt *= axes[r][2]
        v = read(addr, typ, cnt)
        # сверка с дескриптором: объект, которому принадлежит адрес
        o = next((x for a, x in by_addr.items() if a <= addr < a + x.size), None)
        if o is None:
            errs.append(f'{n}: адрес вне объектов'); continue
        off = (addr - BASE - o.data) // ETYPE[o.etype][1]
        ref = o.values(d)[off:off + cnt]
        mask = {'SWORD': 0xFFFF, 'SBYTE': 0xFF}.get(typ)
        got = [x & mask if mask and ETYPE[o.etype][0][0] == 'u' else x for x in v]
        if got != ref:
            errs.append(f'{n}: значения не совпадают с дескриптором')
        nchar += 1
    cal_bytes = sum(o.size for o in objs if o.data is not None and o.in_cal())
    print(f'{a2l}: калибровок {nchar}, осей {len(axes)}, переменных {len(meas)}; '
          f'покрыто {len(covered)} из {cal_bytes} байт таблицы; ошибок {len(errs)}')
    for e in errs[:20]:
        print('   ', e)
    return not errs

if __name__ == '__main__':
    sys.exit(0 if main(sys.argv[1], sys.argv[2]) else 1)
