#!/usr/bin/env python3
"""A2L (ASAM MCD-2 MC 1.6) для M74.9 из таблицы дескрипторов калибровок.

Всё, что знает блок о калибровке, лежит в её дескрипторе (tools/calmap.py):
адрес, тип, размерность, оси. Нет только имён и единиц — их здесь нет и в
прошивке. Поэтому имена служебные: CAL_<индекс> (индекс — тот, что код
передаёт геттеру), оси AX_<индекс>, входы осей AXIN_<индекс>. Где смысл
установлен (notes/), имя и описание осмысленные.

Раскладка данных — по коду геттеров: карта хранится строками по Y,
внутри строки X меняется быстрее всего (смещение = y*nx + x) -> ROW_DIR.
Массивы кривых/карт (несколько штук на дескриптор) разбиты на отдельные
CAL_<индекс>_<k>. Порядок байт little-endian (MSB_LAST).

Адреса — адреса ЭБУ (флеш 0x08000000). В WinOLS при импорте задайте
смещение -0x08000000 (файл начинается с адреса 0).

    mka2l.py <файл.bin> <выход.a2l>
"""
import sys, struct, re
from calmap import load, ETYPE, BASE
from ccflag import SIG, WIN_OFF, OPEN_OFF

A2L_T = {'u8': 'UBYTE', 's8': 'SBYTE', 'u16': 'UWORD', 's16': 'SWORD',
         'u32': 'ULONG', 's32': 'SLONG'}
RANGE = {'u8': (0, 255), 's8': (-128, 127), 'u16': (0, 65535), 's16': (-32768, 32767),
         'u32': (0, 4294967295), 's32': (-2147483648, 2147483647)}

# Пересчёты, установленные по коду (notes/cruise.md)
CM = {
    'CM_RAW':   ('сырое значение', '', 1),
    'CM_KMH64': ('скорость, км/ч (сырое / 64)', 'km/h', 64),
    'CM_C128':  ('температура, °C (сырое / 128)', 'degC', 128),
    'CM_P128':  ('педаль / запрос, % (сырое / 128)', '%', 128),
}

def tname(o):
    return ETYPE[o.etype][0]

def signed_guess(t, vals):
    """u16-объект с явно отрицательными значениями (0xC000+ рядом с малыми) -> s16.
    Геттеры возвращают 16 бит, знак часто задаёт потребитель — по
    дескриптору его не видно."""
    if t == 'u16' and any(v >= 0xC000 for v in vals) and any(v <= 0x4000 for v in vals):
        return 's16'
    return t

def axis_cm(vals, t):
    if t in ('s16', 'u16'):
        sv = [v - 65536 if v > 32767 else v for v in vals]
        if sv == list(range(-5120, 12801, 2560)):
            return 'CM_C128', 's16', 'температура −40…100 °C'
        if sv and sv[0] == 0 and sv[-1] == 12800 and all(a < b for a, b in zip(sv, sv[1:])):
            return 'CM_P128', t, 'педаль 0…100 %'
    if vals == list(range(len(vals))) and len(vals) == 8:
        return 'CM_RAW', t, 'индекс 0…7 (похоже, передача)'
    return 'CM_RAW', t, ''

def known_names(d, objs):
    """Имена по установленному смыслу. Блок круиза — по сигнатуре (одинаково
    у BB03/BB04/BB02), остальное — только при раскладке BB04/BB02."""
    names = {}
    m = SIG.search(d, 0x60000, 0x7FFFC)
    if m:
        b = m.start()
        at = {o.data: o.idx for o in objs if o.data is not None}
        fixed = [(b + 8, 'CRUISE_SUPPORT', 'признак поддержки круиза [?, флаг]', 'CM_RAW'),
                 (b + 26, 'CRUISE_ENABLE', 'круиз-контроль включён (1)', 'CM_RAW'),
                 (b + 27, 'LIMITER_ENABLE', 'ограничитель скорости включён (1)', 'CM_RAW'),
                 (b + OPEN_OFF, 'CRUISE_BTN_OPEN', 'кнопки круиза: верхний порог исправной линии, АЦП', 'CM_RAW')]
        wins = ['CRUISE_BTN_WIN_IDLE', 'CRUISE_BTN_WIN_5', 'CRUISE_BTN_WIN_4A',
                'CRUISE_BTN_WIN_4B', 'CRUISE_BTN_WIN_3']
        for k, n in enumerate(wins):
            fixed.append((b + WIN_OFF + 4 * k, n, 'кнопки круиза: окно [мин, макс] АЦП x4', 'CM_RAW'))
        for addr, n, desc, cm in fixed:
            if addr in at:
                names[at[addr]] = (n, desc, cm)
        # раскладка BB04/BB02: #592 по адресу b+0x106
        if at.get(b + 0x106) == 0x592:
            names[0x592] = ('CRUISE_VSET_MIN', 'минимальная заданная скорость круиза', 'CM_KMH64')
    return names

# Переменные RAM с установленным смыслом: (адрес, имя, тип, пересчёт, описание,
# (смещение литерала в коде, который подтверждает адрес для этой сборки))
KNOWN_RAM = [
    (0x2000157A, 'CRUISE_VSET', 's16', 'CM_KMH64', 'круиз: заданная скорость', 0x84554),
    (0x20001582, 'CRUISE_V', 's16', 'CM_KMH64', 'круиз: текущая скорость (фильтр)', 0x84014),
    (0x2000158C, 'CRUISE_MODE', 'u8', 'CM_RAW', 'круиз: код режима для приборки 0..7', 0x84550),
    (0x2000158A, 'CRUISE_BTN', 'u8', 'CM_RAW', 'круиз: код кнопки (255 — нет)', 0x83984),
    (0x20001560, 'CRUISE_BTN_MASK', 'u16', 'CM_RAW', 'круиз: маска кнопок после антидребезга', 0x84540),
    (0x200015BC, 'CRUISE_BTN_ADC', 's16', 'CM_RAW', 'круиз: АЦП линии кнопок x4', 0x83950),
    (0x20003B9E, 'CRUISE_REQ', 's16', 'CM_P128', 'круиз: запрос вместо педали', 0x86300),
    (0x20003B99, 'CRUISE_ACTIVE', 'u8', 'CM_RAW', 'круиз: запрос активен', 0x862FC),
    (0x20001136, 'PEDAL_DEMAND', 's16', 'CM_P128', 'итоговый запрос педали (или круиза)', 0x182E0),
    (0x200040B4, 'VEH_SPEED', 's16', 'CM_RAW', 'скорость автомобиля (масштаб не проверен)', 0x95800),
]

def ident(s):
    return re.sub(r'[^A-Za-z0-9_]', '_', s)

def build(path):
    d, tb, objs, by_desc = load(path)
    names = known_names(d, objs)
    out, rl, meas, axes_out, chars = [], {}, [], [], []
    seen_ram = set()

    def layout(kind, t, n=0):
        key = (kind, t, n)
        if key not in rl:
            if kind == 'AX':
                nm = f'RL_AX_{A2L_T[t]}_{n}'
                body = f'AXIS_PTS_X 1 {A2L_T[t]} INDEX_INCR DIRECT\n      FIX_NO_AXIS_PTS_X {n}'
            else:
                nm = f'RL_FNC_{A2L_T[t]}'
                body = f'FNC_VALUES 1 {A2L_T[t]} ROW_DIR DIRECT'
            rl[key] = (nm, body)
        return rl[key][0]

    def lim(t, cm):
        lo, hi = RANGE[t]
        f = CM[cm][2]
        return lo / f, hi / f

    # входы осей и оси
    ax_name = {}
    for o in objs:
        if o.what != 'ось' or o.data is None:
            continue
        t0 = tname(o)
        vals = o.values(d)
        cm, t, desc = axis_cm(vals, t0)
        nm = f'AX_{o.idx:03X}'
        ax_name[BASE + o.desc] = (nm, o.n, cm, t)
        inp = f'AXIN_{o.idx:03X}'
        if o.ram and o.ram not in seen_ram:
            seen_ram.add(o.ram)
            lo, hi = lim(t, cm)
            meas.append((inp, f'вход оси {nm}' + (f' ({desc})' if desc else ''), t, cm, lo, hi, o.ram, 1))
        lo, hi = lim(t, cm)
        axes_out.append(f'''  /begin AXIS_PTS {nm} "ось #{o.idx:03X}{', ' + desc if desc else ''}"
    0x{BASE + o.data:08X} {inp if o.ram else 'NO_INPUT_QUANTITY'} {layout('AX', t, o.n)} 0 {cm} {o.n} {lo:g} {hi:g}
  /end AXIS_PTS''')

    for o in objs:
        if o.data is None or not o.in_cal() or o.what == 'ось':
            continue
        vals = o.values(d)
        t = signed_guess(tname(o), vals)
        sz = ETYPE[o.etype][1]
        nm0, desc0, cm = names.get(o.idx, (f'CAL_{o.idx:03X}', '', 'CM_RAW'))
        lo, hi = lim(t, cm)
        note = '' if t == tname(o) else ' [знак по значениям]'
        if o.what in ('знач', 'массив'):
            if o.n == 1:
                chars.append(f'''  /begin CHARACTERISTIC {nm0} "{desc0 or 'значение #%03X' % o.idx}{note}"
    VALUE 0x{BASE + o.data:08X} {layout('FNC', t)} 0 {cm} {lo:g} {hi:g}
  /end CHARACTERISTIC''')
            else:
                chars.append(f'''  /begin CHARACTERISTIC {nm0} "{desc0 or 'массив #%03X' % o.idx}{note}"
    VAL_BLK 0x{BASE + o.data:08X} {layout('FNC', t)} 0 {cm} {lo:g} {hi:g}
    MATRIX_DIM {o.n} 1 1
  /end CHARACTERISTIC''')
            continue
        ax = [ax_name.get(a) for a in o.axes]
        if any(a is None for a in ax):
            continue
        per = o.dims[-1] * (o.dims[-2] if o.what == 'карта' else 1)
        cnt = o.n // per
        for k in range(cnt):
            nm = nm0 if cnt == 1 else f'{nm0}_{k}'
            addr = BASE + o.data + k * per * sz
            descr = []
            for a in ax:
                anm, an, acm, at_ = a
                alo, ahi = lim(at_, acm)
                inp = 'AXIN_' + anm[3:]
                descr.append(f'''    /begin AXIS_DESCR COM_AXIS {inp} {acm} {an} {alo:g} {ahi:g}
      AXIS_PTS_REF {anm}
    /end AXIS_DESCR''')
            kind = 'CURVE' if o.what == 'кривая' else 'MAP'
            what = 'кривая' if kind == 'CURVE' else 'карта'
            dims = 'x'.join(map(str, o.dims[-2:] if kind == 'MAP' else o.dims[-1:]))
            chars.append(f'''  /begin CHARACTERISTIC {nm} "{desc0 or f'{what} #{o.idx:03X} {dims}'}{f' [{k + 1}/{cnt}]' if cnt > 1 else ''}{note}"
    {kind} 0x{addr:08X} {layout('FNC', t)} 0 {cm} {lo:g} {hi:g}
{chr(10).join(descr)}
  /end CHARACTERISTIC''')

    # RAM-величины из таблицы и установленные переменные
    for o in objs:
        if o.what in ('RAM±', 'RAM') and o.ram and o.ram not in seen_ram:
            seen_ram.add(o.ram)
            t = tname(o)
            lo, hi = RANGE[t]
            meas.append((f'RAM_{o.idx:03X}', f'RAM-величина #{o.idx:03X}', t, 'CM_RAW', lo, hi, o.ram, o.n))
    for addr, nm, t, cm, desc, proof in KNOWN_RAM:
        if struct.unpack_from('<I', d, proof)[0] != addr or addr in seen_ram:
            continue
        seen_ram.add(addr)
        lo, hi = lim(t, cm)
        meas.append((nm, desc, t, cm, lo, hi, addr, 1))

    ver = d[0x624C0:0x624D3].split(b'\0')[0].decode('ascii', 'replace') or 'M74.9'
    out.append(f'''ASAP2_VERSION 1 60
/begin PROJECT M74_9 "ИТЭЛМА M74.9, сгенерировано tools/mka2l.py"
  /begin HEADER "из таблицы дескрипторов @0x{tb:05X}, {len(objs)} записей"
    VERSION "{ident(ver)}"
  /end HEADER
/begin MODULE {ident(ver)} "{ver}"
  /begin MOD_COMMON ""
    BYTE_ORDER MSB_LAST
    ALIGNMENT_BYTE 1
    ALIGNMENT_WORD 1
    ALIGNMENT_LONG 1
  /end MOD_COMMON
  /begin MOD_PAR ""
    /begin MEMORY_SEGMENT CODE1 "код" CODE FLASH INTERN 0x08001000 0x5F000 -1 -1 -1 -1 -1
    /end MEMORY_SEGMENT
    /begin MEMORY_SEGMENT CAL "калибровки" DATA FLASH INTERN 0x08060000 0x20000 -1 -1 -1 -1 -1
    /end MEMORY_SEGMENT
    /begin MEMORY_SEGMENT CODE2 "код" CODE FLASH INTERN 0x08080000 0x80000 -1 -1 -1 -1 -1
    /end MEMORY_SEGMENT
  /end MOD_PAR''')
    for nm, (desc, unit, f) in CM.items():
        out.append(f'''  /begin COMPU_METHOD {nm} "{desc}" RAT_FUNC "%.3" "{unit}"
    COEFFS 0 1 0 0 0 {f}
  /end COMPU_METHOD''')
    for nm, body in rl.values():
        out.append(f'''  /begin RECORD_LAYOUT {nm}
      {body}
  /end RECORD_LAYOUT''')
    for nm, desc, t, cm, lo, hi, addr, n in meas:
        md = f'\n    MATRIX_DIM {n} 1 1' if n > 1 else ''
        out.append(f'''  /begin MEASUREMENT {nm} "{desc}" {A2L_T[t]} {cm} 0 0 {lo:g} {hi:g}
    ECU_ADDRESS 0x{addr:08X}{md}
  /end MEASUREMENT''')
    out += axes_out + chars
    out.append('/end MODULE\n/end PROJECT\n')
    stats = dict(axes=len(axes_out), chars=len(chars), meas=len(meas), layouts=len(rl))
    return '\n'.join(out), stats

if __name__ == '__main__':
    text, st = build(sys.argv[1])
    open(sys.argv[2], 'w', encoding='utf-8').write(text)
    print(f'{sys.argv[2]}: осей {st["axes"]}, калибровок {st["chars"]}, '
          f'переменных {st["meas"]}, раскладок {st["layouts"]}')
