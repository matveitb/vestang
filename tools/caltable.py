#!/usr/bin/env python3
"""Разбор таблицы дескрипторов калибровок M74.9.

Запись 12 байт: указатель(4) | тип(2) | флаги(2) | количество(4).
Таблица лежит в области кода и описывает каждую калибровку в 0x60000..0x77000.
Имён в прошивке нет (они в A2L/DAMOS), но адрес, размер и разрядность есть.
"""
import struct, sys

BASE = 0x08000000
CAL_LO, CAL_HI = 0x08060000, 0x08080000

def parse(d, scan=(0x1000, 0x60000)):
    out, off = [], scan[0]
    while off + 12 <= scan[1]:
        ptr, typ, flg, cnt = struct.unpack_from('<IHHI', d, off)
        if CAL_LO <= ptr < CAL_HI and 0 < typ <= 8 and 0 < cnt <= 0x4000:
            out.append((off, ptr - BASE, typ, flg, cnt))
            off += 12
        else:
            off += 2
    return out

def runs(entries, min_len=8):
    """Оставить только длинные непрерывные цепочки записей — отсев случайных совпадений."""
    good, cur = [], []
    for e in entries:
        if cur and e[0] != cur[-1][0] + 12:
            if len(cur) >= min_len: good += cur
            cur = []
        cur.append(e)
    if len(cur) >= min_len: good += cur
    return good

if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    ent = runs(parse(d))
    print(f'записей: {len(ent)}')
    if ent:
        print(f'таблица: {ent[0][0]:06X}..{ent[-1][0]+12:06X}')
        print(f'калибровки: {min(e[1] for e in ent):06X}..{max(e[1] for e in ent):06X}')
    for off, ptr, typ, flg, cnt in ent[:int(sys.argv[2]) if len(sys.argv) > 2 else 0]:
        print(f'  @{off:06X}  кал {ptr:06X}  тип {typ}  флаги {flg:04X}  n={cnt}')
