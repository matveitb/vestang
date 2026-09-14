#!/usr/bin/env python3
"""Хексдамп с абсолютными адресами: hx.py <файл> <смещение> [длина]"""
import sys

def dump(path, off=0, ln=256):
    with open(path, 'rb') as f:
        f.seek(off)
        data = f.read(ln)
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{off+i:06X}  {hexs:<47}  {text}')

if __name__ == '__main__':
    a = sys.argv
    dump(a[1], int(a[2], 0) if len(a) > 2 else 0, int(a[3], 0) if len(a) > 3 else 256)
