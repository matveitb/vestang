#!/usr/bin/env python3
"""Флаги круиз-контроля и ограничителя скорости в прошивках M74.9.

Блок конфигурации круиза опознаётся по соседям в таблице калибровок:

    #n-5  = 03FF        (2 байта)
    #n-4  = 0000 / 0001 признак поддержки круиза в софте
    #n-3  = 00000046    (4 байта)
    #n-2  = 40
    #n-1  = 03
    #n    = круиз-контроль      0 = выкл, 1 = вкл
    #n+1  = ограничитель скорости

Адреса по софтам: BB03 -> 0x63BEA/0x63BEB, BB04 и BB02 -> 0x63BFA/0x63BFB.

Правка калибровок ломает КС, поэтому по умолчанию исходная (заводская) КС
восстанавливается компенсатором на 0x7FFF8 — так же, как делает тюнер.
"""
import sys, struct
from caltable import parse, runs
from m74ks import crc32_m74
from kscomp import solve

CAL_SEG = [(0x60000, 0x7FFFC)]

def find(d):
    """Вернуть (адрес_поддержки, адрес_круиза, адрес_ограничителя) или None."""
    E = runs(parse(d))
    for i in range(5, len(E) - 1):
        p = [E[j][1] for j in range(i - 5, i + 2)]
        if (d[p[0]:p[0]+2] == b'\x03\xFF'
                and d[p[2]:p[2]+4] == b'\x00\x00\x00\x46'
                and d[p[3]] == 0x40 and d[p[4]] == 0x03):
            return p[1], p[5], p[6]
    return None

def show(path):
    d = open(path, 'rb').read()
    got = find(d)
    if not got:
        print(f'{path}: блок круиза не опознан'); return
    sup, cc, lim = got
    print(f'{path}')
    supported = 'есть' if d[sup:sup+2] != bytes(2) else 'НЕТ'
    print(f'   поддержка в софте @{sup:06X} = {d[sup:sup+2].hex().upper()}  ({supported})')
    print(f'   круиз-контроль    @{cc:06X} = {d[cc]}')
    print(f'   ограничитель      @{lim:06X} = {d[lim]}')

def set_cc(path, out, val):
    d = bytearray(open(path, 'rb').read())
    got = find(bytes(d))
    if not got:
        sys.exit('блок круиза не опознан')
    sup, cc, lim = got
    if val and d[sup:sup+2] == bytes(2):
        print('ВНИМАНИЕ: софт помечен как без поддержки круиза (#n-4 = 0000).')
        print('          На таком софте одного флага, скорее всего, мало.')
    keep = crc32_m74(bytes(d), CAL_SEG)      # заводская КС до правки
    d[cc] = d[lim] = 1 if val else 0
    d[0x7FFF8:0x7FFFC] = solve(bytes(d), CAL_SEG, 0x7FFF8, keep)
    open(out, 'wb').write(d)
    print(f'{out}: круиз {"включён" if val else "выключен"}, КС калибровок сохранена {keep:08X}')

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'show':
        for p in sys.argv[2:]: show(p)
    elif cmd in ('on', 'off'):
        set_cc(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else sys.argv[2], cmd == 'on')
