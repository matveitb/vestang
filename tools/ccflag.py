#!/usr/bin/env python3
"""Включение круиз-контроля и ограничителя скорости в прошивках M74.9.

Круиз включается ИСКЛЮЧИТЕЛЬНО калибровками, код не меняется ни на байт.

    BB04: 3 байта — признак поддержки 0x63BE9, круиз 0x63BFA, ограничитель 0x63BFB
          + окна распознавания кнопок (см. ниже)
    BB03: 2 байта — признак поддержки уже стоит, нужны 0x63BEA / 0x63BEB

Кнопки круиза приходят на один вход АЦП (канал 0x12, резистивная лестница).
Функция 0x83760 сравнивает отсчёт x4 с пятью окнами [мин, макс] (u16 x2,
блок +0x11C от начала сигнатуры) и порогом обрыва (s16, +0x22E). У BB02 и
BB03 окна рабочие, у BB04 схлопнуты (мин = макс): ни одна кнопка не
распознаётся, и одних флагов недостаточно. Пары тюнера `+tun KK` для BB04
окна не трогают — поэтому круиз на них не включается.

Блок опознаётся по соседям в таблице калибровок, без привязки к адресам:

    #n-5 = 03FF   #n-4 = признак поддержки   #n-3 = 00000046
    #n-2 = 40     #n-1 = 03                  #n = круиз   #n+1 = ограничитель

КС калибровок по умолчанию пересчитывается честно. С ключом --pin вместо
этого сохраняется исходная КС через компенсатор на 0x7FFF8 — так делает
второй тюнер, чтобы прошивка отдавала заводскую КС.
"""
import sys, struct, re
from m74ks import crc32_m74
from kscomp import solve

CAL_SEG = [(0x60000, 0x7FFFC)]

# Байтовая сигнатура блока — не зависит от раскладки софта и от таблиц.
# 1A 00 C8 00 C8 00 03 FF 00 <sup> FF FF 00 00 00 46
# 40 00 C0 FF 40 00 C0 FF 03 00 <cc> <lim>
SIG = re.compile(
    rb'\x1A\x00\xC8\x00\xC8\x00\x03\xFF\x00(.)\xFF\xFF\x00\x00\x00\x46'
    rb'\x40\x00\xC0\xFF\x40\x00\xC0\xFF\x03\x00(.)(.)', re.S)

# Окна кнопок из BB02/BB03 (одинаковы в обоих): #566 #567 #974 #975 #568
WIN_OFF, OPEN_OFF = 0x11C, 0x22E
WIN_OK = bytes.fromhex('c3061109440511071701fe0275032905aeffb100')
OPEN_OK = 665

def windows(d, base):
    """'ok', 'off' (схлопнуты) или None (не опознаны)."""
    w = d[base + WIN_OFF:base + WIN_OFF + 20]
    if w == WIN_OK:
        return 'ok'
    pairs = struct.unpack('<10H', w)
    if all(pairs[i] == pairs[i + 1] for i in range(0, 10, 2)):
        return 'off'
    return None

def find(d):
    """(адрес признака поддержки, адрес круиза, адрес ограничителя) или None."""
    m = SIG.search(d, 0x60000, 0x7FFFC)
    if not m:
        return None
    base = m.start()
    return base + 8, base + 26, base + 27

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
    base = sup - 8
    st = {'ok': 'рабочие', 'off': 'СХЛОПНУТЫ — кнопки не распознаются', None: 'не опознаны'}
    print(f'   окна кнопок  @{base + WIN_OFF:06X}: {st[windows(d, base)]}, '
          f'порог @{base + OPEN_OFF:06X} = {struct.unpack_from("<h", d, base + OPEN_OFF)[0]}')

def set_cc(path, out, val, pin=False):
    d = bytearray(open(path, 'rb').read())
    got = find(bytes(d))
    if not got:
        sys.exit('блок круиза не опознан')
    sup, cc, lim = got
    keep = crc32_m74(bytes(d), CAL_SEG)
    v = 1 if val else 0
    d[sup+1] = d[cc] = d[lim] = v
    base = sup - 8
    if val:
        st = windows(bytes(d), base)
        if st == 'off':
            d[base + WIN_OFF:base + WIN_OFF + 20] = WIN_OK
            struct.pack_into('<h', d, base + OPEN_OFF, OPEN_OK)
            print('   окна кнопок были схлопнуты — записаны значения BB02/BB03')
        elif st is None:
            print('   ВНИМАНИЕ: окна кнопок не опознаны, оставлены как есть')
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
