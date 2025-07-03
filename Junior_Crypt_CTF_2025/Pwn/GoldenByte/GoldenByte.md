# Golden Byte

El programa toma de entrada un **unsigned long** y  devuelve la flag si se cumplen dos condiciones:
``` C
  local_c = ticket_number;
  uVar1 = local_c;
  local_c._0_2_ = (short)ticket_number;
  local_c = uVar1;
  if (((short)local_c == -0x217) &&
     (local_c._2_2_ = (short)(ticket_number >> 0x10), local_c._2_ 2_ == -0x4120)) {
    jackpot();
  }
```

`(short)local_c == -0x217`: Los 16 bits menos significativos de `ticket_number` deben ser -0x217
`(local_c._2_2_ = (short)(ticket_number >> 0x10), local_c._2_ 2_ == -0x4120)`: Los 16 bits mas significativos de `ticket_number` deben ser -0x4120

Los numeros negativos se representa como complemento a 2 en arquitectura modernas (bits de su equivalente positivo invertidos + 1).

Como la entrada es un **unsigned long** (entero sin signo de 64 bits), truncarlo a un **short** hace que si el bit mas significativo de los 32 bits extraidos es `1` entonces sea negativo:

Aplicando una mascara 0xFFFF extendemos -0x217 a 16 bits. El complemento a 2 se ve claro aqui:
```
>>> bin(0x217 & 0xFFFF)[2:].rjust(16,"0")
'0000001000010111'
>>> bin(-0x217 & 0xFFFF)[2:]
'1111110111101001'
>>> hex(-0x217 & 0xFFFF)
'0xfde9'
```

Como vemos si los bits menos significativos de la entrada son **0xfde9** cumplimos la primera condicion

Sacamos de la misma forma los bits mas significativos y los concatenamos usando right shift y OR:
```
>>> hex(-0x4120 & 0xFFFF)
'0xbee0'
>>> hex((0xbee0 << 16) | 0xfde9)
'0xbee0fde9'
```

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./GoldenByte")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.mf.grsu.by"
port = 9074

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path],env={"FLAG_VAL":"TEST-TEST-TEST"})
r = start()

#========= exploit here ===================
low = -0x217 & 0xFFFF                   # 0xFDE9 (lower 16 bits)
high = (-0x4120) & 0xFFFF               # 0xBEE0 (higher 16 bits)
jackpot_number = (high << 16) | low     # 0xBEE0FDE9 

print("Jackpot number: {} ({})".format(jackpot_number,hex(jackpot_number)))

r.sendlineafter(b"> ", str(jackpot_number).encode())

r.interactive()
```

`grodno{D4dy4_m4TV31_Pr019r4l_kV4rT1RY_V_K421n0_V3D_n3_2N4L_PWN}`


