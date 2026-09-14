#!/usr/bin/env python3
"""Включение круиз-контроля и ограничителя скорости в прошивках M74.9.

Проверено на парах тюнера (`+tun` против `+tun KK`): круиз включается
ИСКЛЮЧИТЕЛЬНО калибровками, код не меняется ни на байт.

    BB04: 3 байта — признак поддержки 0x63BE9, круиз 0x63BFA, ограничитель 0x63BFB
    BB03: 2 байта — признак поддержки уже стоит, нужны 0x63BEA / 0x63BEB

Блок опознаётся по соседям в таблице калибровок, без привязки к адресам:

    #n-5 = 03FF   #n-4 = признак поддержки   #n-3 = 00000046
    #n-2 = 40     #n-1 = 03                  #n = круиз   #n+1 = ограничитель

КС калибровок по умолчанию пересчитывается честно. С ключом --pin вместо
этого сохраняется исходная КС через компенсатор на 0x7FFF8 — так делает
второй тюнер, чтобы прошивка отдавала заводскую КС.
"""
import sys, struct
from caltable import parse, runs
from m74ks import crc32_m74
from kscomp import solve

CAL_SEG = [(0x60000, 0x7FFFC)]

def find(d):
    """(адрес признака поддержки, адрес круиза, адрес ограничителя) или None."""
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
    print(f'   поддержка    @{sup+1:06X} = {d[sup+1]}')
    print(f'   круиз        @{cc:06X} = {d[cc]}')
    print(f'   ограничитель @{lim:06X} = {d[lim]}')

def set_cc(path, out, val, pin=False):
    d = bytearray(open(path, 'rb').read())
    got = find(bytes(d))
    if not got:
        sys.exit('блок круиза не опознан')
    sup, cc, lim = got
    keep = crc32_m74(bytes(d), CAL_SEG)
    v = 1 if val else 0
    d[sup+1] = d[cc] = d[lim] = v
    if pin:
        d[0x7FFF8:0x7FFFC] = solve(bytes(d), CAL_SEG, 0x7FFF8, keep)
        note = f'КС сохранена заводской {keep:08X}'
    else:
        struct.pack_into('<I', d, 0x7FFFC, crc32_m74(bytes(d), CAL_SEG))
        note = f'КС пересчитана -> {struct.unpack_from("<I", d, 0x7FFFC)[0]:08X}'
    open(out, 'wb').write(bytes(d))
    print(f'{out}: круиз {"включён" if val else "выключен"}, {note}')

if __name__ == '__main__':
    a = [x for x in sys.argv[1:] if x != '--pin']
    pin = '--pin' in sys.argv
    if a[0] == 'show':
        for p in a[1:]: show(p)
    elif a[0] in ('on', 'off'):
        set_cc(a[1], a[2] if len(a) > 2 else a[1], a[0] == 'on', pin)
