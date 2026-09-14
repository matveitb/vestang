#!/usr/bin/env python3
"""Подбор компенсирующего слова ("фиксация КС") для прошивок M74.9.

CRC-32 линеен над GF(2), поэтому 4 байта в конце региона можно подобрать так,
чтобы итоговая КС равнялась любому заданному значению — например заводскому.
Именно так тюнер сохраняет стоковую КС после правки калибровок.

Компенсаторы лежат в последних 4 байтах каждого региона:
  0x7FFF8 — для региона калибровок (КС в 0x7FFFC)
  0xFFFF8 — для региона кода       (КС в 0xFFFFC)
"""
import struct
from m74ks import TAB, crc32_m74

def _feed(c, data):
    for b in data:
        c = TAB[((c >> 24) ^ b) & 0xFF] ^ ((c << 8) & 0xFFFFFFFF)
    return c

def solve(data, segments, comp_off, target, init=0xFFFFFFFF):
    """Вернуть 4 байта для comp_off, чтобы CRC(segments) == target."""
    d = bytearray(data)
    # состояние до компенсатора: считаем сегменты, обнулив компенсатор
    d[comp_off:comp_off+4] = b'\x00\x00\x00\x00'
    base = crc32_m74(d, segments, init)
    # столбцы линейного оператора: вклад каждого бита компенсатора
    cols = []
    for i in range(32):
        d[comp_off:comp_off+4] = struct.pack('<I', 1 << i)
        cols.append(crc32_m74(d, segments, init) ^ base)
    # решаем Lin(W) = target ^ base методом Гаусса над GF(2)
    want = target ^ base
    rows = [(cols[i], 1 << i) for i in range(32)]
    sol, piv = 0, {}
    for vec, mask in rows:
        v, m = vec, mask
        while v:
            top = v.bit_length() - 1
            if top in piv:
                pv, pm = piv[top]
                v ^= pv; m ^= pm
            else:
                piv[top] = (v, m); break
    v, m = want, 0
    while v:
        top = v.bit_length() - 1
        if top not in piv:
            return None            # цель недостижима
        pv, pm = piv[top]
        v ^= pv; m ^= pm
    sol = m
    return struct.pack('<I', sol)

if __name__ == '__main__':
    import sys
    from m74ks import REGIONS
    d = open(sys.argv[1], 'rb').read()
    tgt_cal, tgt_code = int(sys.argv[2], 16), int(sys.argv[3], 16)
    print('калибровки 0x7FFF8:', solve(d, [(0x60000, 0x7FFFC)], 0x7FFF8, tgt_cal).hex().upper())
    print('код        0xFFFF8:', solve(d, [(0x1000, 0x60000), (0x80000, 0xFFFFC)], 0xFFFF8, tgt_code).hex().upper())
