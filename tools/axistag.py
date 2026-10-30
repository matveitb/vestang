"""Метки на эмуляторе (tools/axistag.py <bin> <json>): Метки: известным переменным RAM — уникальные значения; прогон всех функций;
на входе в функции поиска по оси пишем (индекс оси, входное значение)."""
import sys, struct, json
sys.path.insert(0, __import__("os").path.dirname(__file__))
from unicorn import *; from unicorn.arm_const import *
from emu_fuzz import candidates
import axisin
B=0x08000000; SRAM=0x20000000; MAGIC=0x08FFFFF0
img=open(sys.argv[1],'rb').read()
TAGS=json.loads(sys.argv[2])   # {"адрес_hex": [значение, "имя"]}
uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
uc.mem_map(B,0x100000,UC_PROT_READ|UC_PROT_EXEC); uc.mem_write(B,img); uc.mem_map(SRAM,0x40000)
for a,s in ((0x40000000,0x10000000),(0xE0000000,0x100000),(0x22000000,0x2000000)): uc.mem_map(a,s)
uc.mem_map(MAGIC&~0xFFF,0x1000); uc.mem_write(0xE000ED88,struct.pack('<I',0xF00000))
uc.hook_add(UC_HOOK_MEM_READ,lambda u,a,ad,s,v,_: u.mem_write(ad,b'\xff'*s),begin=0x40000000,end=0x4FFFFFFF)
def unm(u,a,ad,s,v,_):
    try: u.mem_map(ad&~0xFFFFF,0x100000)
    except UcError: pass
    return True
uc.hook_add(UC_HOOK_MEM_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED,unm)
sp,pc=struct.unpack_from('<II',img,0x1000); uc.reg_write(UC_ARM_REG_SP,sp)
try: uc.emu_start(pc,B+0x100000,count=2_000_000)
except UcError: pass
snap=bytearray(uc.mem_read(SRAM,0x40000))
for a,(v,n) in TAGS.items():
    struct.pack_into('<h',snap,int(a,16)-SRAM,v)
snap=bytes(snap)
log=[]
funcs=axisin.axis_funcs(img)
for f in funcs:
    uc.hook_add(UC_HOOK_CODE,lambda u,ad,sz,_: log.append((u.reg_read(UC_ARM_REG_R1),u.reg_read(UC_ARM_REG_R2)&0xFFFF)),begin=B+f,end=B+f)
res={}
for f in candidates(img):
    uc.mem_write(SRAM,snap); uc.reg_write(UC_ARM_REG_SP,sp-0x400); uc.reg_write(UC_ARM_REG_LR,MAGIC|1)
    for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3): uc.reg_write(r,0)
    log.clear()
    try: uc.emu_start(B+f+1,MAGIC,count=40000)
    except UcError: pass
    for idx,val in log:
        res.setdefault(idx,set()).add(val)
val2name={v&0xFFFF:n for a,(v,n) in TAGS.items()}
out={}
for idx,vals in sorted(res.items()):
    hit=sorted({val2name[v] for v in vals if v in val2name})
    if hit: out[idx]=hit
print(json.dumps({f'{k:03X}':v for k,v in out.items()},ensure_ascii=False))
