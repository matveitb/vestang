#!/usr/bin/env python3
"""Двухрежимные прошивки MR2 (бензин / ГБО): настройка переключения, Евро, круиз.

Устройство — notes/dual-mode.md. Коротко: второй (ГБО) набор калибровок
лежит копией в зоне кода, геттеры переключаются на него по флагу режима.
Флаг ставит процедура MR2 (BB04: 0xB9EC0); её поведение задаёт бит 0 байта
настройки (BB04: 0xCD871):

    0  режим = ДК2 ниже порога (ДК2 замкнут на массу) — так во всех файлах
    1  педаль газа > 64% при неработающем двигателе (обороты < 200) — переключить;
       после сброса блока всегда бензин

    mr2.py show   <файл>
    mr2.py build  <MR2-файл> <выход> [--pedal] [--cruise] [--noe2 <ref-без-E2> <ref-E2>]

--noe2: объекты, которыми ref-E2 отличается от ref-без-E2 (тот же софт и
тюнинг), переписываются значениями ref-без-E2 в обоих наборах — только если
в обоих наборах MR2 сейчас стоят значения ref-E2. Обе КС пересчитываются.
"""
import sys, struct
from m74ks import crc32_m74, REGIONS
from calmap import load, ETYPE
from ccflag import SIG, WIN_OFF, OPEN_OFF, WIN_OK, OPEN_OK, windows

# Код MR2 начинается сразу за штатным кодом (BB04 0xB9E40, BB03/BB02 раньше)
ZONE = (0xB0000, 0xFFFF8)

def gas_offset(d):
    """Сдвиг ГБО-набора относительно 0x60000 (копия калибровок в зоне MR2)."""
    i = d.find(d[0x60000:0x60100], *ZONE)
    return None if i < 0 else i - 0x60000

def cfg_addr(d):
    """Адрес байта настройки: литерал перед `tst.w r3,#1` после `cmp r7,#0xaa`."""
    j = d.find(bytes.fromhex('aa2f'), *ZONE)
    while j >= 0:
        k = d.find(bytes.fromhex('13f0010f'), j, j + 0x40)
        if k >= 0:
            h = struct.unpack_from('<H', d, k - 4)[0]
            if h >> 11 == 0b01001:
                lit = (k & ~3) + (h & 0xFF) * 4
                return struct.unpack_from('<I', d, lit)[0] - 0x08000000
        j = d.find(bytes.fromhex('aa2f'), j + 1, ZONE[1])
    return None

def cruise_blocks(d, off):
    """Базы блока круиза в бензиновом и ГБО-наборе."""
    out = []
    for lo, hi in ((0x60000, 0x7FFFC), (0x60000 + off, 0x77000 + off)):
        m = SIG.search(d, lo, hi)
        out.append(m.start() if m else None)
    return out

def show(path):
    d = open(path, 'rb').read()
    off, ca = gas_offset(d), cfg_addr(d)
    print(path)
    if off is None or ca is None:
        print('   не MR2 (ГБО-набор или процедура переключения не найдены)'); return
    print(f'   ГБО-набор: 0x60000{off:+X} = {0x60000 + off:05X}')
    mode = 'педаль' if d[ca] & 1 else 'ДК2'
    print(f'   настройка @{ca:05X} = {d[ca]:#04x} -> переключение: {mode}')
    for name, b in zip(('бензин', 'ГБО'), cruise_blocks(d, off)):
        if b is None:
            print(f'   {name:6}: блок круиза не опознан'); continue
        w = {'ok': 'рабочие', 'off': 'схлопнуты', None: '?'}[windows(d, b)]
        print(f'   {name:6}: поддержка {d[b + 9]} круиз {d[b + 26]} огр {d[b + 27]}, окна кнопок {w}')

def build(src, out, pedal=False, cruise=False, noe2=None):
    d = bytearray(open(src, 'rb').read())
    off, ca = gas_offset(d), cfg_addr(d)
    if off is None or ca is None:
        sys.exit('не MR2')
    if pedal:
        d[ca] |= 1
        print(f'   переключение педалью: @{ca:05X} = {d[ca]:#04x}')
    if cruise:
        for name, b in zip(('бензин', 'ГБО'), cruise_blocks(bytes(d), off)):
            if b is None:
                sys.exit(f'блок круиза в наборе {name} не опознан')
            d[b + 9] = d[b + 26] = d[b + 27] = 1
            st = windows(bytes(d), b)
            if st == 'off':
                d[b + WIN_OFF:b + WIN_OFF + 20] = WIN_OK
                struct.pack_into('<h', d, b + OPEN_OFF, OPEN_OK)
            elif st is None:
                sys.exit(f'окна кнопок в наборе {name} не опознаны')
            print(f'   круиз ({name}): флаги 1, окна кнопок рабочие')
    if noe2:
        dn, _, on, _ = load(noe2[0])
        de, _, oe, _ = load(noe2[1])
        n, mapped = 0, set()
        for a, b in zip(on, oe):
            if a.data is None or not a.in_cal():
                continue
            mapped.update(range(a.data, a.data + a.size))
            if a.values(dn) == b.values(de):
                continue
            _, sz, f = ETYPE[a.etype]
            fmt = '<%d%s' % (a.n, f)
            for addr in (a.data, a.data + off):
                if list(struct.unpack_from(fmt, d, addr)) != b.values(de):
                    sys.exit(f'#{a.idx:03X} @{addr:05X}: в MR2 не значение E2-образца — не трогаю')
                struct.pack_into(fmt, d, addr, *a.values(dn))
            n += 1
        # E2 трогает и байты вне карты (хвост калибровок); компенсатор и КС не в счёт
        raw = [i for i in range(0x60000, 0x7FFF8) if dn[i] != de[i] and i not in mapped]
        for i in raw:
            for addr in (i, i + off):
                if d[addr] != de[i]:
                    sys.exit(f'@{addr:05X}: в MR2 не значение E2-образца — не трогаю')
                d[addr] = dn[i]
        print(f'   без E2: {n} объектов и {len(raw)} байт вне карты переписаны в обоих наборах')
    for name, segs, at in REGIONS:
        struct.pack_into('<I', d, at, crc32_m74(d, segs))
        print(f'   КС {name}: {struct.unpack_from("<I", d, at)[0]:08X}')
    open(out, 'wb').write(bytes(d))
    print(f'записано: {out}')

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        print(__doc__)
    elif a[0] == 'show':
        for p in a[1:]:
            show(p)
    elif a[0] == 'build':
        noe2 = None
        if '--noe2' in a:
            i = a.index('--noe2')
            noe2 = (a[i + 1], a[i + 2])
        build(a[1], a[2], '--pedal' in a, '--cruise' in a, noe2)
