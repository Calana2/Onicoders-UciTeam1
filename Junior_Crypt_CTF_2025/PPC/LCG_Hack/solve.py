#!/usr/bin/env python3
from pwn import *

p = remote('ctf.mf.grsu.by', 9042)

a = 2**15 - 1
b = 2**51 - 1

# --- Getting the module ---
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil('Следующее число: ')
r0_line = p.recvline().strip()
m = int(r0_line)

# --- Getting a random number X1 ---
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil('Следующее число: ')
r1_line = p.recvline().strip()
x1 = int(r1_line)
log.info(f"Получен второй номер (x1): {x1}")


# --- Sending the next number ---
prediction = (a * x1 + b) % m
p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil('Ваше число: ')
p.sendline(str(prediction).encode())

# --- Getting the flag ---
result = p.recvall().decode()
print(result)

p.close()
