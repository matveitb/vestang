#!/usr/bin/env python3
"""Контрольные суммы прошивок Bosch M74.9 (Artery AT32F4xx).

Алгоритм: CRC-32, полином 0x04C11DB7, MSB-first (без рефлексии),
init 0xFFFFFFFF, без финального XOR. Результат хранится little-endian.
Таблица в самой прошивке лежит по flash+0x52A64, обработчик — flash+0x0B570C.
Дескрипторы регионов инициализируются в flash+0x0B5740.

Две суммы:
  КС калибровок : регион 0x60000..0x7FFFB          -> хранится в 0x7FFFC
  КС кода       : 0x1000..0x5FFFF + 0x80000..0xFFFFB -> хранится в 0xFFFFC

  m74ks.py check <файл>...      проверить
  m74ks.py fix   <файл> [выход] пересчитать и записать
"""
import sys, struct

POLY = 0x04C11DB7

def _table():
    t = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ POLY) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        t.append(c)
    return t

TAB = _table()

# (имя, [сегменты], смещение хранимой КС)
REGIONS = [
    ('калибровки', [(0x60000, 0x7FFFC)], 0x7FFFC),
    ('код',        [(0x1000, 0x60000), (0x80000, 0xFFFFC)], 0xFFFFC),
]

def crc32_m74(data, segments, init=0xFFFFFFFF):
    c = init
    for s, e in segments:
        for b in data[s:e]:
            c = TAB[((c >> 24) ^ b) & 0xFF] ^ ((c << 8) & 0xFFFFFFFF)
    return c

def check(path):
    d = open(path, 'rb').read()
    ok = True
    rows = []
    for name, segs, at in REGIONS:
        calc = crc32_m74(d, segs)
        stored = struct.unpack_from('<I', d, at)[0]
        good = calc == stored
        ok &= good
        rows.append((name, at, calc, stored, good))
    return ok, rows, d

def fix(path, out):
    d = bytearray(open(path, 'rb').read())
    for _, segs, at in REGIONS:
        struct.pack_into('<I', d, at, crc32_m74(d, segs))
    open(out, 'wb').write(d)
    return out

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'check':
        for p in sys.argv[2:]:
            ok, rows, _ = check(p)
            print(f'{"OK  " if ok else "БИТО"}  {p}')
            for name, at, calc, stored, good in rows:
                mark = '' if good else '   <-- НЕ СХОДИТСЯ'
                print(f'        {name:<11} @{at:06X}  расчёт {calc:08X}  записано {stored:08X}{mark}')
    elif cmd == 'fix':
        out = sys.argv[3] if len(sys.argv) > 3 else sys.argv[2]
        print('записано:', fix(sys.argv[2], out))
