#!/usr/bin/env python3
"""Цепочка доступа к калибровке M74.9: адрес -> дескриптор -> индекс в таблице.

Рабочий код не адресует калибровки напрямую. Доступ идёт через геттер
(BB04: flash+0x48DC) с двойной косвенностью:

    r0 = таблица указателей на дескрипторы, r1 = индекс
    дескриптор = таблица[r1]           ; ldr.w r0, [r0, r1, lsl #2]
    тип        = дескриптор[1]         ; ldrb  r3, [r0, #1]
    значение   = *(дескриптор+8)       ; читается по типу (0x3E2A / 0x3E38 / 0x3EB2)

Дескриптор, 12 байт:
    +0 флаги | +1 тип | +2 разрядность | +4 количество (4 б) | +8 указатель на значение

Поэтому поиск литералов на адрес калибровки находит только дескриптор, а не
код: сам адрес код никогда не держит.

Ищем от якоря — от известного адреса калибровки, — а не глобальной эвристикой.
"""
import sys, struct

BASE = 0x08000000
CODE_LO, CODE_HI = 0x1000, 0x60000

def descriptors_for(d, cal_addr):
    """Дескрипторы, чьё поле +8 указывает на cal_addr."""
    want = struct.pack('<I', BASE + cal_addr)
    out, pos = [], CODE_LO
    while True:
        i = d.find(want, pos, CODE_HI)
        if i < 0:
            break
        pos = i + 1
        if (i - 8) >= CODE_LO and i % 4 == 0:
            out.append(i - 8)
        elif (i - 8) >= CODE_LO:
            out.append(i - 8)
    return out

def plausible_desc(d, p):
    if not (CODE_LO <= p and p + 12 <= len(d)):
        return False
    ptr = struct.unpack_from('<I', d, p + 8)[0]
    # значение может лежать в калибровках, в RAM или во флеш-константах
    return (BASE <= ptr < BASE + 0x100000) or (0x20000000 <= ptr < 0x20040000)

def table_slot(d, desc):
    """Найти элемент таблицы, ссылающийся на дескриптор, и границы таблицы."""
    want = struct.pack('<I', BASE + desc)
    slots, pos = [], CODE_LO
    while True:
        i = d.find(want, pos, CODE_HI)
        if i < 0:
            break
        pos = i + 4
        if i % 4:
            continue
        # раскручиваем таблицу назад и вперёд по валидным элементам
        lo = i
        while lo - 4 >= CODE_LO:
            v = struct.unpack_from('<I', d, lo - 4)[0]
            if not plausible_desc(d, v - BASE):
                break
            lo -= 4
        hi = i + 4
        while hi + 4 <= CODE_HI:
            v = struct.unpack_from('<I', d, hi)[0]
            if not plausible_desc(d, v - BASE):
                break
            hi += 4
        slots.append((i, lo, (hi - lo) // 4, (i - lo) // 4))
    return slots

def code_literals(d):
    """Все 32-битные литералы в коде — среди них лежит база таблицы указателей."""
    out = set()
    for off in range(CODE_LO, CODE_HI - 4, 4):
        out.add(struct.unpack_from('<I', d, off)[0])
    return out

def bases_for(d, slot, lits):
    """Возможные базы таблицы: литерал, от которого slot даёт разумный индекс."""
    res = []
    for v in lits:
        b = v - BASE
        if CODE_LO <= b < slot and (slot - b) % 4 == 0:
            idx = (slot - b) // 4
            if 0 < idx < 0x4000:
                res.append((b, idx))
    return sorted(res, key=lambda x: -x[0])[:3]

def report(d, cal_addr):
    print(f'кал {cal_addr:06X}:')
    descs = [p for p in descriptors_for(d, cal_addr) if plausible_desc(d, p)]
    if not descs:
        print('   дескриптор не найден')
        return
    for p in descs:
        flags, typ = d[p], d[p+1]
        width = struct.unpack_from('<H', d, p + 2)[0]
        cnt = struct.unpack_from('<I', d, p + 4)[0]
        print(f'   дескриптор @{p:06X}  флаги {flags:02X}  тип {typ}  разрядность {width}  n={cnt}')
        lits = code_literals(d)
        for slot, lo, n, idx in table_slot(d, p):
            print(f'      элемент @{slot:06X}')
            for b, i in bases_for(d, slot, lits):
                print(f'         база таблицы @{b:06X} -> ИНДЕКС {i:#x}')

if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    for a in sys.argv[2:]:
        report(d, int(a, 16))
