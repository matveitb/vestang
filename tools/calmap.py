#!/usr/bin/env python3
"""Карта калибровок M74.9 по таблице дескрипторов.

Код обращается к калибровкам только через геттеры (flash+0x48DC и соседи):
    дескриптор = таблица[индекс];  вид = дескриптор[1]
Таблица — массив указателей на дескрипторы, перед ним лежит u32 с их числом
(BB04: число @0x416D0 = 2545, таблица @0x416D4). Ищется по этой сигнатуре,
поэтому работает на всех трёх софтах без привязки к адресам.

Байт +0 — тип элемента: бит 0 = знак, биты 1..2 = размер.
    0 u8   1 s8   2 u16   3 s16   4 u32   5 s32
Байт +1 — вид (по нему ветвится каждый геттер):
    0 значение/массив    1 кривая    2 карта
u16 +2 — класс хранения. Для вида 0 различает:
    0          ось:      +4 RAM позиция (u16 idx<<8|frac), +8 шаг, +A n-1,
                         +C RAM входная величина, +10 точки, +14 индексы
    4, 12, 20  значение: +4 n (u32), +8 указатель
    3, 11      RAM-величина с пределами: +4 n, +8 RAM, +C мин, +10 макс
    8, 9, 16   RAM-массив: +4 n, +8 RAM
Кривая: +4 n точек, +6 число кривых, +8 ось, +C данные.
Карта:  +4 nx, +6 ny, +8 число карт (u32), +C ось X, +10 ось Y, +14 данные.

Проверено: у всех 653 кривых и карт BB04 размер совпадает с n осей.
Имён и физических единиц в прошивке нет — их даёт только A2L.

    calmap.py list  <файл> [--all]       все объекты (по умолчанию — лежащие в калибровках)
    calmap.py show  <файл> <индекс>      значения с осями
    calmap.py diff  <файл-база> <файл>   какие объекты отличаются
    calmap.py cover <файл>               какая доля калибровок покрыта картой
"""
import sys, struct, signal

BASE = 0x08000000
CAL_LO, CAL_HI = 0x60000, 0x80000
ETYPE = {0: ('u8', 1, 'B'), 1: ('s8', 1, 'b'), 2: ('u16', 2, 'H'),
         3: ('s16', 2, 'h'), 4: ('u32', 4, 'I'), 5: ('s32', 4, 'i')}
KIND = {0: 'знач', 1: 'кривая', 2: 'карта'}

def u16(d, o): return struct.unpack_from('<H', d, o)[0]
def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def flash(a): return BASE <= a < BASE + 0x100000

def find_table(d):
    """u32 N, за которым N указателей на дескрипторы во флеше."""
    for off in range(0x1000, 0x60000, 4):
        n = u32(d, off)
        if not 500 <= n <= 0x4000:
            continue
        ok = True
        for i in range(n):
            v = u32(d, off + 4 + 4 * i)
            if not (BASE + 0x1000 <= v < BASE + 0x60000):
                ok = False
                break
        if ok:
            return off + 4, n
    raise SystemExit('таблица дескрипторов не найдена')

class Obj:
    """Один объект таблицы. data — смещение данных в образе (если во флеше)."""
    def __init__(self, d, idx, p):
        self.idx, self.desc = idx, p
        self.etype, self.kind, self.cls = d[p], d[p + 1], u16(d, p + 2)
        self.what, self.data, self.n, self.dims, self.axes = None, None, 0, (), ()
        self.ram = self.lim = None
        et = ETYPE.get(self.etype)
        if et is None:
            return
        k, c = self.kind, self.cls
        if k == 0 and c == 0:
            self.what = 'ось'
            self.n = u16(d, p + 0xA) + 1
            self.dims = (self.n,)
            self.data = u32(d, p + 0x10)
            self.ram = u32(d, p + 0xC)
        elif k == 0 and c in (4, 12, 20):
            self.what = 'знач' if u32(d, p + 4) == 1 else 'массив'
            self.n = u32(d, p + 4)
            self.dims = (self.n,)
            self.data = u32(d, p + 8)
        elif k == 0 and c in (3, 11):
            self.what = 'RAM±'
            self.n = u32(d, p + 4)
            self.ram = u32(d, p + 8)
            self.lim = (u32(d, p + 0xC), u32(d, p + 0x10))
        elif k == 0 and c in (8, 9, 16):
            self.what = 'RAM'
            self.n = u32(d, p + 4)
            self.ram = u32(d, p + 8)
        elif k == 1:
            self.what = 'кривая'
            npt, cnt = u16(d, p + 4), u16(d, p + 6)
            self.dims = (npt,) if cnt == 1 else (cnt, npt)
            self.n = npt * cnt
            self.axes = (u32(d, p + 8),)
            self.data = u32(d, p + 0xC)
        elif k == 2:
            self.what = 'карта'
            nx, ny, cnt = u16(d, p + 4), u16(d, p + 6), u32(d, p + 8)
            self.dims = (ny, nx) if cnt == 1 else (cnt, ny, nx)
            self.n = nx * ny * cnt
            self.axes = (u32(d, p + 0xC), u32(d, p + 0x10))
            self.data = u32(d, p + 0x14)
        if self.what is None or not 0 < self.n <= 0x10000:
            self.what = self.data = self.ram = None
            return
        if self.data is not None and not flash(self.data):
            self.ram, self.data = self.data, None
        elif self.data is not None:
            self.data -= BASE
            if self.data + self.size > len(d):
                self.what = self.data = None

    @property
    def size(self):
        return self.n * ETYPE[self.etype][1] if self.data is not None else 0

    def in_cal(self):
        return self.data is not None and CAL_LO <= self.data < CAL_HI

    def values(self, d):
        _, sz, f = ETYPE[self.etype]
        return list(struct.unpack_from('<%d%s' % (self.n, f), d, self.data))

def load(path):
    d = open(path, 'rb').read()
    tb, n = find_table(d)
    objs = [Obj(d, i, u32(d, tb + 4 * i) - BASE) for i in range(n)]
    by_desc = {o.desc: o for o in objs}
    return d, tb, objs, by_desc

def axis_ref(by_desc, a):
    o = by_desc.get(a - BASE)
    return f'#{o.idx:03X}' if o else f'@{a - BASE:05X}'

def describe(o, by_desc):
    if o.what is None:
        return f'#{o.idx:03X}  @{o.desc:05X}  ?  вид {o.kind} класс {o.cls}'
    t = ETYPE[o.etype][0]
    dims = '×'.join(map(str, o.dims)) if o.dims else str(o.n)
    where = f'{o.data:05X}..{o.data + o.size:05X}' if o.data is not None else \
            (f'RAM {o.ram - 0x20000000:05X}' if o.ram else '-')
    s = f'#{o.idx:03X}  {o.what:<6} {t:<3} {dims:<9} {where}'
    if o.axes:
        s += '  оси ' + ' '.join(axis_ref(by_desc, a) for a in o.axes)
    if o.what == 'ось' and o.ram:
        s += f'  вход RAM {o.ram - 0x20000000:05X}'
    if o.lim:
        s += f'  пределы {o.lim[0] - BASE:05X}/{o.lim[1] - BASE:05X}'
    return s

def cmd_list(path, every=False):
    d, tb, objs, by_desc = load(path)
    print(f'# {path}: таблица @{tb:05X}, объектов {len(objs)}')
    for o in objs:
        if every or o.in_cal():
            print(describe(o, by_desc))

def cmd_cover(path):
    d, tb, objs, by_desc = load(path)
    used = bytearray(CAL_HI - CAL_LO)
    for o in objs:
        if o.in_cal():
            for a in range(o.data, min(o.data + o.size, CAL_HI)):
                used[a - CAL_LO] += 1
    over = sum(1 for u in used if u > 1)
    # пределы RAM-величин — тоже калибровки, но обычно уже описаны как значения
    for o in objs:
        for a in o.lim or ():
            a -= BASE
            if CAL_LO <= a < CAL_HI:
                for b in range(a, min(a + ETYPE[o.etype][1] * o.n, CAL_HI)):
                    used[b - CAL_LO] |= 1
    nonff = [i for i in range(CAL_HI - CAL_LO - 8) if d[CAL_LO + i] != 0xFF]
    cov = sum(1 for i in nonff if used[i])
    from collections import Counter
    kinds = Counter(o.what for o in objs)
    print(f'объектов: {dict(kinds)}')
    print(f'непустых байт в калибровках: {len(nonff)}, покрыто картой: {cov} '
          f'({100 * cov / len(nonff):.1f}%), перекрытий: {over}')
    # непокрытые участки
    runs, s = [], None
    for i in nonff:
        if not used[i]:
            if s is None or i != e + 1:
                if s is not None:
                    runs.append((s, e))
                s = i
            e = i
    if s is not None:
        runs.append((s, e))
    print(f'непокрытых участков: {len(runs)}; крупнейшие:')
    for s, e in sorted(runs, key=lambda r: r[0] - r[1])[:10]:
        print(f'   {CAL_LO + s:05X}..{CAL_LO + e + 1:05X}  {e - s + 1} б')

def fmt_row(vals):
    return ' '.join(f'{v:6d}' for v in vals)

def cmd_show(path, idx):
    d, tb, objs, by_desc = load(path)
    o = objs[idx]
    print(describe(o, by_desc))
    if o.data is None:
        return
    v = o.values(d)
    axes = [by_desc.get(a - BASE) for a in o.axes]
    ax = [a.values(d) if a and a.data is not None else None for a in axes]
    if o.what == 'карта':
        nx, ny = o.dims[-1], o.dims[-2]
        print('        X: ' + fmt_row(ax[0]) if ax[0] else '')
        for m in range(o.n // (nx * ny)):
            for r in range(ny):
                y = f'{ax[1][r]:6d}' if ax[1] else '      '
                row = v[(m * ny + r) * nx:(m * ny + r + 1) * nx]
                print(f'  {y} | ' + fmt_row(row))
            print()
    elif o.what == 'кривая':
        npt = o.dims[-1]
        if ax[0]:
            print('     X: ' + fmt_row(ax[0]))
        for m in range(o.n // npt):
            print('     Y: ' + fmt_row(v[m * npt:(m + 1) * npt]))
    else:
        for i in range(0, len(v), 16):
            print('   ' + fmt_row(v[i:i + 16]))

def cmd_diff(pa, pb):
    da, _, oa, _ = load(pa)
    db, _, ob, by_b = load(pb)
    if len(oa) != len(ob):
        print(f'разное число объектов ({len(oa)} / {len(ob)}) — сравнивайте один софт')
        return
    hit = set()
    for a, b in zip(oa, ob):
        if a.data is None or b.data is None or a.size != b.size:
            continue
        va, vb = a.values(da), b.values(db)
        ch = [i for i in range(len(va)) if va[i] != vb[i]]
        if ch:
            for x in range(b.data, b.data + b.size):
                hit.add(x)
            print(f'{describe(b, by_b)}   изменено {len(ch)}/{len(va)}')
    # байты калибровок вне карты
    rest = [i for i in range(CAL_LO, CAL_HI) if da[i] != db[i] and i not in hit]
    if rest:
        print(f'вне карты отличаются {len(rest)} байт: ' +
              ' '.join(f'{i:05X}' for i in rest[:16]) + (' ...' if len(rest) > 16 else ''))

if __name__ == '__main__':
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    a = sys.argv[1:]
    if not a:
        print(__doc__)
    elif a[0] == 'list':
        cmd_list(a[1], '--all' in a)
    elif a[0] == 'cover':
        cmd_cover(a[1])
    elif a[0] == 'show':
        cmd_show(a[1], int(a[2], 16))
    elif a[0] == 'diff':
        cmd_diff(a[1], a[2])
